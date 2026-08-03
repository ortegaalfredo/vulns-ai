#!/usr/bin/env python3
"""
Advanced LLM Interactor Tool with Enhanced Memory System
A sophisticated command-line tool that provides shell access and task planning
capabilities to Large Language Models through function calling, with persistent
memory using SQLite and text file storage.

This version supports two presentation modes:
  --nogui  : Original direct-CLI behaviour (stdout/stderr, no TUI)
  default  : Textual-based TUI with split panels (prompt, console, agent output,
             status footer) and an /autoapprove toggle for the approval gate.

The agent logic (LLMInteractor) is presentation-agnostic: all I/O is funnelled
through an EventSink interface.  ConsoleSink replicates the original CLI
behaviour.  TUISink bridges events to the Textual app via a thread-safe queue.
"""

import argparse
import json
import subprocess
import sys
import time
import threading
import queue
import re
import signal
import os
import pty
import select
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from openai import OpenAI
import sqlite3
from pathlib import Path

try:
    # Textual is only required for TUI mode; --nogui runs without it.
    import textual
    from textual.app import App, ComposeResult
    from textual.widgets import RichLog, Input, Static
    from textual.containers import Horizontal, Vertical
    from textual import events
    from textual.binding import Binding
    _TEXTUAL_AVAILABLE = True
except ImportError:
    _TEXTUAL_AVAILABLE = False


# Color codes for output (used by ConsoleSink and ANSI stripping in TUISink)
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


class CommandTimeoutError(Exception):
    """Exception raised when command execution times out"""
    pass


# ---------------------------------------------------------------------------
# ANSI stripping helper (used by TUISink to strip raw \033[...] codes before
# pushing events to the Textual app, which applies its own Rich styling).
# ---------------------------------------------------------------------------
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from text."""
    return _ANSI_RE.sub('', text)


# ---------------------------------------------------------------------------
# EventSink abstraction
# ---------------------------------------------------------------------------
# The sink interface decouples LLMInteractor's I/O from the presentation
# layer.  ConsoleSink replicates the original direct-terminal behaviour
# (--nogui mode).  TUISink pushes events to a queue that the Textual app
# polls from the main thread; the agent thread NEVER touches widgets
# directly.
#
# All direct print()/input()/sys.exit() calls that were scattered through
# LLMInteractor are funnelled through sink.emit()/sink.input() so the same
# agent code runs unchanged in either mode.


class EventSink:
    """Abstract I/O interface for LLMInteractor.

    Implementations:
        ConsoleSink  – direct terminal I/O (--nogui mode, backward compatible)
        TUISink      – queue bridge to Textual app (TUI mode)

    The agent code calls only these methods; it never touches print/input
    directly.  This makes the agent presentation-agnostic.
    """

    def emit(self, kind: str, payload: dict):
        """Output an event.

        kind values:
            LOG              – general informational output
            ERROR            – error / warning output
            LLM_STREAM       – streamed LLM content (token-by-token)
            THINKING_STREAM  – streamed reasoning/thinking content
            CMD_EXEC         – command is about to be executed
            CMD_OUTPUT       – raw command output chunk
            CMD_COMPLETE     – command finished with exit code
            SYSTEM           – system banner (model, API base, config)
            STATUS_UPDATE    – footer status update (tok/s, iteration, etc.)
            APPROVAL_REQUEST – command awaiting approval
            SHUTDOWN         – agent is shutting down
        payload fields depend on kind; common keys: text, end, flush.
        """
        raise NotImplementedError("emit() must be implemented by subclass")

    def input(self, prompt: str) -> str:
        """Request a line of user input.  Used by the approval gate.
        Returns the user's response string."""
        raise NotImplementedError("input() must be implemented by subclass")

    def close(self):
        """Release any resources held by the sink."""
        raise NotImplementedError("close() must be implemented by subclass")


class ConsoleSink(EventSink):
    """Sink for --nogui mode.  Replicates the original direct-terminal
    behaviour exactly: stdout/stderr via print(), stdin via builtins.input().
    No queueing, no threading, no TUI – a thin adapter that preserves the
    historical CLI behaviour bit-for-bit."""

    def __init__(self):
        import builtins
        self._builtins = builtins

    def emit(self, kind: str, payload: dict):
        text = payload.get("text", "")
        if kind == "STATUS_UPDATE":
            return  # status footer is meaningless in CLI mode
        # Streaming kinds (LLM tokens, thinking tokens) must NOT add a
        # newline after each token; the caller controls line breaks by
        # emitting explicit \n characters or by sending a final LOG event.
        if kind in ("LLM_STREAM", "THINKING_STREAM"):
            end = ""
        else:
            end = payload.get("end", "\n")
        flush = payload.get("flush", True)
        # Apply colour per event kind
        if kind == "ERROR":
            print(f"{colors.RED}{text}{colors.END}", file=sys.stderr, end=end, flush=flush)
        elif kind == "LLM_STREAM":
            print(f"{colors.CYAN}{text}{colors.END}", end=end, flush=flush)
        elif kind == "THINKING_STREAM":
            print(f"{colors.MAGENTA}{text}{colors.END}", end=end, flush=flush)
        elif kind == "CMD_OUTPUT":
            print(f"{colors.GREEN}{text}{colors.END}", end=end, flush=flush)
        elif kind == "CMD_EXEC":
            print(f"{colors.YELLOW}{text}{colors.END}", end=end, flush=flush)
        elif kind == "CMD_COMPLETE":
            print(f"{colors.BOLD}{text}{colors.END}", end=end, flush=flush)
        elif kind == "SYSTEM":
            print(f"{colors.BOLD}{colors.BLUE}{text}{colors.END}", end=end, flush=flush)
        else:
            print(text, end=end, flush=flush)

    def input(self, prompt: str) -> str:
        return self._builtins.input(prompt)

    def close(self):
        pass


class TUISink(EventSink):
    """Sink for TUI mode.  All emit() calls are serialised and pushed to a
    thread-safe queue.  The Textual app (main thread) polls the queue via
    set_interval and renders events to widgets.  The agent thread NEVER
    touches widgets or Textual objects directly.

    The input() method implements the approval gate:
        - auto_approve True  → return "y" immediately (no blocking)
        - auto_approve False → push APPROVAL_REQUEST event, block on a
                               threading.Event until the TUI user types
                               /approve or /reject, or stop_event is set
    """

    def __init__(self, event_queue: queue.Queue, stop_event: threading.Event):
        self.queue = event_queue
        self.stop_event = stop_event
        self.auto_approve = False
        # Approval gate state – single-slot because the agent processes one
        # command at a time.
        self._approval_event: Optional[threading.Event] = None
        self._approval_response: Optional[str] = None

    def emit(self, kind: str, payload: dict):
        if self.stop_event.is_set():
            return
        # Strip ANSI codes; the TUI applies its own styling via Rich markup
        clean = {}
        for k, v in payload.items():
            clean[k] = _strip_ansi(v) if isinstance(v, str) else v
        self.queue.put({"kind": kind, "payload": clean})

    def input(self, prompt: str) -> str:
        # Fast path: auto-approve enabled → no blocking
        if self.auto_approve:
            self.emit("LOG", {"text": "[AUTO-APPROVED] " + prompt})
            return "y"

        # Push an approval request event so the TUI can display it
        self.emit("APPROVAL_REQUEST", {"command": prompt})

        # Block until the TUI user resolves the request or the agent is
        # shutting down.  Poll every 100 ms so we can react to stop_event.
        self._approval_event = threading.Event()
        self._approval_response = None
        while not self._approval_event.is_set():
            if self.stop_event.is_set():
                self._approval_event = None
                self._approval_response = None
                return "n"  # reject on shutdown
            self._approval_event.wait(0.1)

        response = self._approval_response or "n"
        self._approval_event = None
        self._approval_response = None
        return response

    def resolve_approval(self, approved: bool, suggestion: str = ""):
        """Called by the TUI (main thread) when the user responds to a
        pending approval request.  /approve → approved=True;
        /reject → approved=False; /suggest <text> → approved=False,
        suggestion=<text>."""
        if approved:
            self._approval_response = "y"
        else:
            self._approval_response = suggestion if suggestion else "n"
        if self._approval_event:
            self._approval_event.set()

    def close(self):
        self.stop_event.set()
        if self._approval_event:
            self._approval_event.set()  # unblock any waiting approval


class MemoryManager:
    """Manages persistent memory storage using SQLite and text files"""

    def __init__(self, db_path: str = "llm_memory.db", backup_dir: str = "memory_backups"):
        self.db_path = db_path
        self.backup_dir = backup_dir
        self._initialize_database()
        self._ensure_backup_directory()

    def _initialize_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create memories table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS memories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                category TEXT DEFAULT 'general',
                importance INTEGER DEFAULT 1,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                tags TEXT,
                access_count INTEGER DEFAULT 0,
                last_accessed DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create conversations table for conversation history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memories_category ON memories(category)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memories_importance ON memories(importance)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_memories_timestamp ON memories(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_conversations_session ON conversations(session_id)')

        conn.commit()
        conn.close()

    def _ensure_backup_directory(self):
        """Ensure backup directory exists"""
        Path(self.backup_dir).mkdir(exist_ok=True)

    def store_memory(self, content: str, category: str = "general", importance: int = 1, tags: str = "") -> int:
        """Store a new memory in the database"""
        # Clamp importance to the schema-defined range (1-5)
        importance = max(1, min(5, importance))
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO memories (content, category, importance, tags)
            VALUES (?, ?, ?, ?)
        ''', (content, category, importance, tags))

        memory_id = cursor.lastrowid
        conn.commit()
        conn.close()

        # Create text backup
        self._backup_memory_to_file(memory_id, content, category, importance, tags)

        return memory_id

    def retrieve_memories(self, limit: int = 10, category: str = None, min_importance: int = 1,
                          search_query: str = None) -> List[Dict[str, Any]]:
        """Retrieve memories with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = '''
            SELECT id, content, category, importance, timestamp, tags, access_count
            FROM memories
        '''
        conditions = []
        params = []

        if category:
            conditions.append("category = ?")
            params.append(category)

        if min_importance is not None:
            conditions.append("importance >= ?")
            params.append(min_importance)

        if search_query:
            conditions.append("(content LIKE ? OR tags LIKE ?)")
            params.extend([f"%{search_query}%", f"%{search_query}%"])

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY importance DESC, timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        results = cursor.fetchall()

        # Update access count and last accessed time
        for row in results:
            memory_id = row[0]
            cursor.execute('''
                UPDATE memories
                SET access_count = access_count + 1, last_accessed = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (memory_id,))

        conn.commit()
        conn.close()

        # Convert to list of dictionaries
        memories = []
        for row in results:
            memories.append({
                'id': row[0],
                'content': row[1],
                'category': row[2],
                'importance': row[3],
                'timestamp': row[4],
                'tags': row[5],
                'access_count': row[6]
            })

        return memories

    def search_memories(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Search memories by content or tags"""
        return self.retrieve_memories(limit=limit, search_query=query)

    def delete_memory(self, memory_id: int) -> bool:
        """Delete a memory by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('DELETE FROM memories WHERE id = ?', (memory_id,))
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()

        if deleted:
            # Remove backup file
            backup_file = Path(self.backup_dir) / f"memory_{memory_id}.txt"
            if backup_file.exists():
                backup_file.unlink()

        return deleted

    def _backup_memory_to_file(self, memory_id: int, content: str, category: str, importance: int, tags: str):
        """Create a text backup of a memory"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        backup_content = f"""Memory ID: {memory_id}
Timestamp: {timestamp}
Category: {category}
Importance: {importance}
Tags: {tags}
Content:
{content}
"""

        backup_file = Path(self.backup_dir) / f"memory_{memory_id}.txt"
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write(backup_content)

    def store_conversation(self, session_id: str, role: str, content: str):
        """Store conversation history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO conversations (session_id, role, content)
            VALUES (?, ?, ?)
        ''', (session_id, role, content))

        conn.commit()
        conn.close()

    def get_conversation_history(self, session_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve conversation history for a session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT role, content, timestamp
            FROM conversations
            WHERE session_id = ?
            ORDER BY timestamp ASC
            LIMIT ?
        ''', (session_id, limit))

        results = cursor.fetchall()
        conn.close()

        history = []
        for row in results:
            history.append({
                'role': row[0],
                'content': row[1],
                'timestamp': row[2]
            })

        return history


class LLMInteractor:
    """Main class for LLM interactor functionality with enhanced memory"""

    def __init__(self, api_base: str, model: str, api_key: str, auto_approve: bool = False,
                  memory_enabled: bool = True, show_thinking: bool = True, command_timeout: int = 30,
                  max_prompt_len: int = 20000, max_output_bytes: int = 10240, debug: bool = False,
                  sink: EventSink = None):
        self.base_url = api_base.rstrip('/')
        self.model = model
        self.api_key = api_key
        self.auto_approve = auto_approve
        self.memory_enabled = memory_enabled
        self.conversation_history = []
        self.max_iterations = 500
        self.max_tokens = 8000
        self.command_timeout = command_timeout
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.show_thinking = show_thinking
        self.max_prompt_len = max_prompt_len
        self.max_output_bytes = max_output_bytes
        self.debug = debug

        # Sink for presentation-layer I/O.  Default to ConsoleSink so the
        # agent is usable without a TUI (backward-compatible --nogui path).
        self.sink: EventSink = sink if sink is not None else ConsoleSink()

        # Shutdown coordination – checked between iterations and before
        # each command execution so the TUI can halt the agent cleanly.
        self.stop_event = threading.Event()

        # Initialize OpenAI client
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url
        )

        # Initialize memory manager
        if memory_enabled:
            self.memory_manager = MemoryManager()
        else:
            self.memory_manager = None

        # Enhanced tool schemas
        self.tool_schemas = [
            {
                "type": "function",
                "function": {
                    "name": "execute_bash",
                    "description": "Execute a bash command in the terminal",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "The bash command to execute"
                            }
                        },
                        "required": ["command"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "store_memory",
                    "description": "Store important information in persistent memory for future access",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "The content to store in memory"
                            },
                            "category": {
                                "type": "string",
                                "description": "Category for the memory (e.g., 'project', 'user_preference', 'technical_note', 'learning')",
                                "enum": ["general", "project", "user_preference", "technical_note", "learning", "configuration", "bug_fix", "algorithm"]
                            },
                            "importance": {
                                "type": "integer",
                                "description": "Importance level (1-5, where 5 is most important)",
                                "minimum": 1,
                                "maximum": 5
                            },
                            "tags": {
                                "type": "string",
                                "description": "Comma-separated tags for easier searching (optional)"
                            }
                        },
                        "required": ["content"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "retrieve_memories",
                    "description": "Retrieve stored memories with optional filtering",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of memories to retrieve",
                                "default": 10
                            },
                            "category": {
                                "type": "string",
                                "description": "Filter by category (optional)",
                                "enum": ["general", "project", "user_preference", "technical_note", "learning", "configuration", "bug_fix", "algorithm"]
                            },
                            "min_importance": {
                                "type": "integer",
                                "description": "Filter by minimum importance level (1-5)",
                                "minimum": 1,
                                "maximum": 5
                            },
                            "search_query": {
                                "type": "string",
                                "description": "Search in memory content and tags (optional)"
                            }
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "search_memories",
                    "description": "Search memories by content or tags",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results",
                                "default": 10
                            }
                        },
                        "required": ["query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "delete_memory",
                    "description": "Delete a memory by ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "memory_id": {
                                "type": "integer",
                                "description": "The ID of the memory to delete"
                            }
                        },
                        "required": ["memory_id"]
                    }
                }
            }
        ]

    def _log(self, message: str, end: str = '\n', flush: bool = True):
        """Emit a log event via the sink."""
        self.sink.emit("LOG", {"text": message, "end": end, "flush": flush})

    def _log_error(self, message: str):
        """Emit an error event via the sink."""
        self.sink.emit("ERROR", {"text": message})

    # --- Single-source-of-truth constants ---
    COMPLETION_MARKER = "TASKCOMPLETE"
    OUTPUT_TRUNCATION_SENTINEL = "output too long: truncated"

    def _get_message_length(self, msg: dict) -> int:
        """Get the length of a message content, handling None values."""
        content = msg.get('content', '')
        return len(content) if content is not None else 0

    def _dump_conversation_history(self):
        """Dump the current conversation history to interactor-debug.txt for debugging."""
        with open("interactor-debug.txt", "w", encoding="utf-8") as f:
            f.write(f"Conversation history dump at {datetime.now().isoformat()}\n")
            f.write(f"Total messages: {len(self.conversation_history)}\n")
            total_len = sum(self._get_message_length(msg) for msg in self.conversation_history)
            f.write(f"Total content length: {total_len}\n")
            f.write(f"Max prompt length: {self.max_prompt_len}\n")
            f.write("=" * 80 + "\n\n")
            for i, msg in enumerate(self.conversation_history):
                role = msg.get('role', 'unknown')
                content = msg.get('content', '') or ''
                tool_calls = msg.get('tool_calls', [])
                tool_call_id = msg.get('tool_call_id', '')
                f.write(f"--- Message {i} (role: {role}) ---\n")
                if tool_call_id:
                    f.write(f"tool_call_id: {tool_call_id}\n")
                if tool_calls:
                    f.write(f"tool_calls: {json.dumps(tool_calls, indent=2)}\n")
                f.write(f"content ({len(content)} chars):\n{content}\n\n")
            f.write("=" * 80 + "\nEnd of conversation history\n")
        self._log(f"[DEBUG DUMP] Conversation history dumped to interactor-debug.txt")

    def _truncate_conversation_history(self):
        """Truncate conversation history if it exceeds max_prompt_len.

        Keeps the system prompt (index 0) and the first user instruction (index 1),
        then reduces size from the oldest messages onwards.  Two passes:

          1. Condense oversized tool outputs in-place (cheap, preserves structure).
          2. Drop the oldest messages (index 2 onwards) until under the limit.

        This actually shrinks the list, unlike the previous implementation which
        only mutated tool content in-place and never removed messages.
        """
        total_len = sum(self._get_message_length(msg) for msg in self.conversation_history)

        if total_len <= self.max_prompt_len:
            return

        self._log(f"[TRUNCATING] Prompt length ({total_len}) exceeds max ({self.max_prompt_len}). Truncating conversation history.")

        # Pass 1: condense oversized tool outputs in-place.
        for msg in self.conversation_history:
            if msg.get('role') == 'tool' and isinstance(msg.get('content'), str) and len(msg['content']) > 30:
                removed_len = len(msg['content'])
                msg['content'] = '<condensed tool output>'
                total_len -= (removed_len - len(msg['content']))
                self._log(f"[TRUNCATED] Condensed tool message (removed {removed_len} chars)")

        # Pass 2: drop the oldest messages (keep system at 0 and first user at 1).
        # Iterate by index and only advance when we keep a message, so popped
        # entries are naturally skipped without going out of range.
        i = 2
        while i < len(self.conversation_history) and total_len > self.max_prompt_len:
            removed_msg = self.conversation_history.pop(i)
            total_len -= self._get_message_length(removed_msg)
            self._log(f"[TRUNCATED] Removed {removed_msg.get('role')} message (removed {self._get_message_length(removed_msg)} chars, new length: {total_len})")

        # Safety: never drop the system prompt or the first user instruction.
        # If we somehow still exceed the limit (e.g. a single enormous system
        # prompt), stop rather than corrupt the conversation.
        final_len = sum(self._get_message_length(msg) for msg in self.conversation_history)
        self._log(f"[TRUNCATING COMPLETE] Final prompt length: {final_len}")

    def get_system_prompt(self) -> str:
        """Get the enhanced system prompt for the LLM with memory instructions"""
        marker = self.COMPLETION_MARKER
        truncation_sentinel = self.OUTPUT_TRUNCATION_SENTINEL
        timeout_seconds = self.command_timeout
        output_limit = self.max_output_bytes

        base_prompt = f"""You are an expert planning and execution assistant. Fulfill the user's request by breaking it into manageable steps and executing bash commands via the execute_bash tool (one command at a time, waiting for each result).

**Workflow:**
1. Analyze the request; if complex, break it into a numbered task list.
2. Restate your plan every ~5 steps and update the task list as you progress.
3. Execute one step with execute_bash, then evaluate the result.
4. If a step fails, adjust your approach and explain. If all steps are done and the goal is met, emit the exact phrase '{marker}'.
5. Only emit '{marker}' once you are certain every necessary action is complete and verified. Never say it prematurely.

**Runtime Constraints (execute_bash):**
- Output is capped at {output_limit} bytes. If truncated, the literal sentinel `{truncation_sentinel}` is appended. If you see it, you are missing data — do NOT assume success or failure. Re-run with output redirected to a file and read in chunks via `sed -n 'start,end p' file`, or use `head -c N`/`tail -c N`. Prefer targeted commands (grep, wc, stat) over dumping large outputs.
- Commands are killed after {timeout_seconds}s. For long operations use `nohup ... &` and check later, split into smaller steps, or set your own `timeout`.
- Commands run in a PTY; use non-interactive flags (`-y`, `--no-interactive`) where available.

**Command Results:**
- Never echo command execution metadata (e.g. "[EXECUTING]", "exit code X") into your response content; the tool system supplies that.
- Only describe your plan, your reasoning, and conclusions drawn from the REAL tool output. Never fabricate or guess command output — wait for the actual result.

**Internet Access:**
- Use `ddgr --json --unsafe --np "query"`, wget/curl, and the w3m browser for up-to-date information.

**Persistence Policy (CRITICAL):**
- Keep working until the task is genuinely complete. Do NOT stop early or produce a summary-only final response — take concrete action with tools.
- If you respond without calling tools, the system injects a continuation prompt; you must keep making progress.
- Troubleshoot errors and try alternative approaches until the objective is met.
- The ONLY way to finish is to emit '{marker}' AFTER verifying all objectives via actual command execution and result inspection. Partial completion is not completion.
- Do not ask the user for clarification unless you have exhausted autonomous options.
- Before emitting '{marker}', verify your last actions (check file contents, run tests, confirm services).

Think carefully; response quality is the highest priority. You have unlimited thinking tokens."""
        if self.memory_enabled:
            memory_prompt = """

**MEMORY SYSTEM:** You have access to a persistent memory system that allows you to store and retrieve information across sessions. Use it strategically:

**Memory Management Strategies:**
1. **Store Important Information:** When you learn something valuable (configurations, file paths, user preferences, technical solutions, project details), use `store_memory` to save it.
2. **Retrieve Relevant Context:** When starting a new task or dealing with a similar problem, use `retrieve_memories` or `search_memories` to find helpful information.
3. **Categorize Appropriately:** Use categories like:
   - 'technical_note' for technical knowledge
   - 'project' for project-specific information
   - 'user_preference' for user preferences
   - 'configuration' for system settings
   - 'bug_fix' for bug solutions
   - 'learning' for new concepts learned
4. **Prioritize by Importance:** Rate information 1-5 based on importance (5 = critical)
5. **Add Tags:** Use descriptive tags for easier searching later

**Memory Functions Available:**
- `store_memory`: Save important information
- `retrieve_memories`: Get filtered memories
- `search_memories`: Search by content/tags
- `delete_memory`: Remove outdated memories

**Example Usage:**
- When learning a user's preference: store their preference as 'user_preference' with high importance
- When fixing a bug: store the solution as 'bug_fix' with relevant tags
- When configuring a system: store settings as 'configuration'
- When learning new technical information: store as 'technical_note' or 'learning'

Use memory to build long-term knowledge and provide better, more consistent assistance across sessions."""
            return base_prompt + memory_prompt

        return base_prompt

    def execute_bash_command(self, command: str) -> Tuple[str, int]:
        """Execute a bash command with timeout and return output and exit code"""
        self._log(f"\n[EXECUTING] {command}")

        output_buffer = bytearray()

        try:
            import fcntl
        except ImportError:
            self._log_error("'fcntl' module not available. This PTY-based interactor requires a Unix-like system.")
            return "fcntl module not available", 1

        pid, master_fd = pty.fork()

        if pid == 0:
            # Best-effort, start a new process group so os.killpg(pid, ...) targets
            # the child's group rather than the parent's. In sandboxes that forbid
            # setsid (EPERM), we fall back to running in the parent's group; the
            # killpg calls in the parent are guarded by try/except OSError already.
            try:
                os.setsid()
            except OSError:
                pass
            try:
                os.execvp("/bin/sh", ["/bin/sh", "-c", command])
            except OSError as e:
                os.write(2, f"Child process error (os.execvp failed): {e}\n".encode('utf-8'))
                os._exit(1)
            # os.execvp only returns on error; this line is unreachable on success
            os._exit(0)

        exit_code = -1
        timed_out = False

        master_fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
        fcntl.fcntl(master_fd, fcntl.F_SETFL, master_fl | os.O_NONBLOCK)

        # In TUI mode (TUISink), Textual/curses owns the terminal and sys.stdin.
        # Modifying stdin flags or including it in select() will freeze the UI.
        # Only monitor stdin in ConsoleSink (--nogui) mode.
        _monitor_stdin = not isinstance(self.sink, TUISink)
        stdin_fl = None
        if _monitor_stdin:
            stdin_fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
            fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, stdin_fl | os.O_NONBLOCK)

        # Derive the output kill threshold from the configurable max_output_bytes
        # (5x the limit) instead of a hardcoded 50KB, so the two stay in sync.
        output_kill_threshold = 5 * self.max_output_bytes

        start_time = time.time()
        try:
            while True:
                if self.stop_event.is_set():
                    self._log_error("[STOP] Agent shutdown requested. Terminating command.")
                    try:
                        os.killpg(pid, signal.SIGTERM)
                        time.sleep(0.5)
                        os.killpg(pid, signal.SIGKILL)
                    except OSError:
                        pass
                    break

                if time.time() - start_time > self.command_timeout:
                    self._log_error(f"[TIMEOUT] Command timed out after {self.command_timeout} seconds. Sending SIGTERM.")
                    os.killpg(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except OSError:
                        pass
                    timed_out = True
                    break

                # Only include sys.stdin in select when not in TUI mode.
                _read_fds = [master_fd, sys.stdin.fileno()] if _monitor_stdin else [master_fd]
                rlist, _, _ = select.select(_read_fds, [], [], 0.1)

                if master_fd in rlist:
                    try:
                        data = os.read(master_fd, 1024)
                        if data:
                            output_buffer.extend(data)
                            # Stream output to the sink in real-time
                            try:
                                chunk_text = data.decode('utf-8', errors='replace')
                                self.sink.emit("CMD_OUTPUT", {"text": chunk_text, "command": command})
                            except Exception:
                                pass
                            if len(output_buffer) > output_kill_threshold:
                                self._log_error(f"[OUTPUT LIMIT] Command output exceeded {output_kill_threshold} bytes. Stopping command.")
                                os.killpg(pid, signal.SIGTERM)
                                time.sleep(0.3)
                                try:
                                    os.waitpid(pid, os.WNOHANG)
                                except OSError:
                                    pass
                                break
                        else:
                            break
                    except OSError:
                        break

                if _monitor_stdin and sys.stdin.fileno() in rlist:
                    try:
                        user_input = os.read(sys.stdin.fileno(), 1024)
                        if user_input:
                            os.write(master_fd, user_input)
                    except OSError:
                        pass

                try:
                    wpid, status = os.waitpid(pid, os.WNOHANG)
                    if wpid == pid:
                        exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else \
                                    (os.WTERMSIG(status) + 128)
                        break
                except OSError:
                    break

        finally:
            if master_fd is not None:
                os.close(master_fd)

            # Only restore stdin flags when we modified them.
            if stdin_fl is not None:
                try:
                    fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, stdin_fl)
                except (OSError, AttributeError):
                    pass

            if exit_code == -1:
                # The main loop exited without observing the child's exit status
                # (e.g., PTY reached EOF before the status was seen).  Use a
                # blocking waitpid(pid, 0) so the OS reaps the now-dead child
                # and returns its TRUE exit status.
                #
                # The previous code used WNOHANG, which returns (0, 0) for
                # "still running".  That is indistinguishable from the
                # "exited normally, code 0" case, causing a false-positive
                # "Command still running after timeout" message even for
                # instant commands like `grep`.  Blocking here is correct
                # because the child has already exited by now.
                try:
                    _, status = os.waitpid(pid, 0)
                    if os.WIFEXITED(status):
                        exit_code = os.WEXITSTATUS(status)
                    elif os.WIFSIGNALED(status):
                        exit_code = os.WTERMSIG(status) + 128
                    else:
                        exit_code = 1
                except OSError:
                    # ESRCH: child already reaped.  ECHILD: not our child.
                    # Nothing to report; do not fabricate a "still running"
                    # message.
                    pass

        final_output = output_buffer.decode('utf-8', errors='replace')

        # Clean carriage returns: remove \r characters to avoid ^M display issues
        # and normalize line endings to Unix style (\n)
        final_output = final_output.replace('\r\n', '\n').replace('\r', '\n')

        # Truncate output if it exceeds max_output_bytes
        output_bytes = len(final_output.encode('utf-8'))
        if output_bytes > self.max_output_bytes:
            final_output = final_output[:self.max_output_bytes] + "\n" + self.OUTPUT_TRUNCATION_SENTINEL

        # Notify sink of command completion
        self.sink.emit("CMD_COMPLETE", {"command": command, "exit_code": exit_code, "output": final_output})

        # Raise CommandTimeoutError if the command timed out, so the caller's
        # except CommandTimeoutError handler is reachable.
        if timed_out:
            raise CommandTimeoutError(f"Command timed out after {self.command_timeout} seconds")

        return final_output, exit_code

    def handle_store_memory(self, args: Dict[str, Any]) -> str:
        """Handle store_memory function call"""
        if not self.memory_manager:
            return "Memory system is not enabled"

        content = args.get('content', '')
        category = args.get('category', 'general')
        importance = args.get('importance', 1)
        tags = args.get('tags', '')

        memory_id = self.memory_manager.store_memory(content, category, importance, tags)

        return f"Memory stored successfully with ID {memory_id}. Category: {category}, Importance: {importance}"

    def handle_retrieve_memories(self, args: Dict[str, Any]) -> str:
        """Handle retrieve_memories function call"""
        if not self.memory_manager:
            return "Memory system is not enabled"

        limit = args.get('limit', 10)
        category = args.get('category')
        min_importance = args.get('min_importance')
        search_query = args.get('search_query')

        memories = self.memory_manager.retrieve_memories(
            limit=limit, category=category, min_importance=min_importance, search_query=search_query
        )

        if not memories:
            return "No memories found matching the criteria."

        result = f"Retrieved {len(memories)} memories:\n\n"
        for memory in memories:
            result += f"ID: {memory['id']} | Category: {memory['category']} | Importance: {memory['importance']} | Tags: {memory['tags']}\n"
            result += f"Content: {memory['content']}\n"
            result += f"Timestamp: {memory['timestamp']} | Accessed: {memory['access_count']} times\n\n"

        return result.strip()

    def handle_search_memories(self, args: Dict[str, Any]) -> str:
        """Handle search_memories function call"""
        if not self.memory_manager:
            return "Memory system is not enabled"

        query = args.get('query', '')
        limit = args.get('limit', 10)

        memories = self.memory_manager.search_memories(query, limit)

        if not memories:
            return f"No memories found matching query: '{query}'"

        result = f"Found {len(memories)} memories matching '{query}':\n\n"
        for memory in memories:
            result += f"ID: {memory['id']} | Category: {memory['category']} | Importance: {memory['importance']}\n"
            result += f"Content: {memory['content']}\n\n"

        return result.strip()

    def handle_delete_memory(self, args: Dict[str, Any]) -> str:
        """Handle delete_memory function call"""
        if not self.memory_manager:
            return "Memory system is not enabled"

        memory_id = args.get('memory_id')

        deleted = self.memory_manager.delete_memory(memory_id)

        if deleted:
            return f"Memory {memory_id} deleted successfully."
        else:
            return f"Memory {memory_id} not found."

    def get_user_confirmation(self, command: str) -> Tuple[bool, Optional[str]]:
        """Get user confirmation for command execution via the sink"""
        if self.auto_approve:
            self._log(f"[AUTO-APPROVED] {command}")
            return True, None

        # Ask the sink for approval.  ConsoleSink uses builtins.input() (CLI);
        # TUISink blocks on an Event until the TUI user types /approve or /reject.
        prompt = f"Approve command? (y/n/suggestion): {command}"
        response_input = self.sink.input(prompt).strip().lower()

        if response_input in ['y', 'yes', '']:
            return True, None
        elif response_input in ['n', 'no']:
            return False, None
        else:
            return False, response_input

    def _validate_messages(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate and sanitize messages before sending to API.

        Ensures all messages have valid content (not None) and proper structure.
        """
        validated = []
        for msg in messages:
            # Create a copy to avoid modifying the original
            clean_msg = dict(msg)

            # Ensure content is never None - use empty string instead
            if clean_msg.get("content") is None:
                # If it's a tool message without content, that's okay if it has tool_call_id
                if clean_msg.get("role") == "tool" and clean_msg.get("tool_call_id"):
                    clean_msg["content"] = ""
                elif clean_msg.get("role") == "assistant" and clean_msg.get("tool_calls"):
                    # Assistant messages with tool_calls can have empty content
                    clean_msg["content"] = ""
                else:
                    # For other messages, set to empty string
                    clean_msg["content"] = ""

            # Ensure role is valid
            valid_roles = ["system", "user", "assistant", "tool", "developer", "function"]
            if clean_msg.get("role") not in valid_roles:
                # Skip invalid messages or set a default
                continue

            # Tool messages must have tool_call_id
            if clean_msg.get("role") == "tool" and not clean_msg.get("tool_call_id"):
                # Skip tool messages without tool_call_id
                continue

            # Function messages must have name
            if clean_msg.get("role") == "function" and not clean_msg.get("name"):
                # Skip function messages without name
                continue

            validated.append(clean_msg)

        # Safety check: prevent consecutive assistant messages at the end of the list.
        # Many API providers reject this pattern with errors like:
        # "Cannot have 2 or more assistant messages at the end of the list."
        # This can happen when a previous turn ended with an assistant message
        # (no tool calls) and the caller attempts to send another request.
        while len(validated) >= 2 and validated[-1].get("role") == "assistant" and validated[-2].get("role") == "assistant":
            # Remove the older of the two consecutive assistant messages
            validated.pop(-2)

        # If the last message is an assistant message (no tool calls), we cannot
        # proceed - the API would have to produce another assistant message.
        # Return empty list to signal the caller to stop.
        if len(validated) >= 1 and validated[-1].get("role") == "assistant":
            # Check if the last assistant message has tool_calls
            last_msg = validated[-1]
            has_tool_calls = bool(last_msg.get("tool_calls"))
            if not has_tool_calls:
                # The last message is an assistant message without tool calls.
                # This is a terminal state - we cannot continue without violating
                # the API's constraint. Signal the caller by returning an empty list.
                # The caller should check for empty list and terminate the loop.
                return []

        return validated

    def call_llm_api(self, messages: List[Dict[str, str]], use_tools: bool = True) -> Dict[str, Any]:
        """Call the LLM API using the OpenAI client with streaming support"""

        # Validate and sanitize messages before sending
        messages = self._validate_messages(messages)

        # Safety check: if _validate_messages returns an empty list, it means
        # the conversation history ends with an assistant message without tool calls.
        # This is a terminal state - calling the API would produce consecutive
        # assistant messages which APIs reject. Return a terminal response.
        if not messages:
            self._log(f"\n[SAFETY STOP] Conversation history validation returned empty - terminal assistant state detected. Ending interaction.")
            return {
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": f"I have completed my response. No further actions are needed.\n\n{self.COMPLETION_MARKER}",
                        "tool_calls": None,
                        "reasoning_content": None
                    }
                }]
            }

        # Lower temperature when tools are in play: high randomness (1.0) makes
        # models emit malformed/incorrect JSON tool arguments.  A deterministic
        # temperature (~0.2) yields far more reliable function calls.  Creative
        # text-only turns keep the original higher temperature.
        temperature = 0.2 if use_tools else 1.0

        if self.model.find("gpt")==-1: # OpenAI don't like this
            request_params = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "stream": True,
                "max_tokens": self.max_tokens,
            }
            request_params['extra_body'] = {"chat_template_kwargs": {"enable_thinking": True}}
        else:
            request_params = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "stream": True,
                }

        if use_tools:
            request_params["tools"] = self.tool_schemas
            request_params["tool_choice"] = "auto"

        max_retries = 5
        wait_seconds = 60

        for attempt in range(1, max_retries + 1):
            try:
                self._log(f"\n[LLM STREAMING RESPONSE] ", end="", flush=True)

                collected_content = ""
                collected_thinking = ""
                collected_tool_calls = []
                in_thinking = False
                thinking_buffer = ""

                stream = self.client.chat.completions.create(**request_params)

                for chunk in stream:
                        if self.stop_event.is_set():
                            self._log("\n[STOP] Agent shutdown requested. Aborting LLM stream.")
                            return {
                                "choices": [{
                                    "message": {
                                        "role": "assistant",
                                        "content": f"Agent stopped by user.\n\n{self.COMPLETION_MARKER}",
                                        "tool_calls": None,
                                        "reasoning_content": None
                                    }
                                }]
                            }
                        delta = chunk.choices[0].delta if chunk.choices else None

                        if delta:
                            # Handle thinking/reasoning tokens if enabled and supported.
                            # Some APIs use 'thinking', others (e.g. DeepSeek/OpenAI) use 'reasoning_content'.
                            reasoning_chunk = None
                            if hasattr(delta, 'reasoning_content') and delta.reasoning_content is not None:
                                reasoning_chunk = delta.reasoning_content
                            elif hasattr(delta, 'thinking') and delta.thinking:
                                reasoning_chunk = delta.thinking

                            if self.show_thinking and reasoning_chunk:
                                collected_thinking += reasoning_chunk
                                thinking_buffer += reasoning_chunk

                                # Emit thinking tokens to the sink in real-time
                                self.sink.emit("THINKING_STREAM", {"text": reasoning_chunk})
                                in_thinking = True

                            # Handle regular content
                            if delta.content:
                                content_chunk = delta.content
                                collected_content += content_chunk

                                # If we were in thinking mode, show transition
                                if self.show_thinking and in_thinking and thinking_buffer:
                                    self._log("\n[THINKING COMPLETE]")
                                    in_thinking = False

                                # Emit content chunk to the sink in real-time
                                self.sink.emit("LLM_STREAM", {"text": content_chunk})

                            if delta.tool_calls:
                                for tool_call_chunk in delta.tool_calls:
                                    index = tool_call_chunk.index

                                    while len(collected_tool_calls) <= index:
                                        collected_tool_calls.append({
                                            "id": "",
                                            "type": "function",
                                            "function": {
                                                "name": "",
                                                "arguments": ""
                                            }
                                        })

                                    current_tool_call = collected_tool_calls[index]

                                    if tool_call_chunk.id:
                                        current_tool_call["id"] = tool_call_chunk.id

                                    if tool_call_chunk.function:
                                        if tool_call_chunk.function.name:
                                            current_tool_call["function"]["name"] += tool_call_chunk.function.name
                                        if tool_call_chunk.function.arguments:
                                            current_tool_call["function"]["arguments"] += tool_call_chunk.function.arguments
                break
            except Exception as e:
                if attempt < max_retries:
                    self._log(f"[API ERROR] Connection error: {str(e)}. Retrying in {wait_seconds}s... (attempt {attempt}/{max_retries})")
                    time.sleep(wait_seconds)
                else:
                    raise
                continue

        self._log("")
        final_tool_calls = [tc for tc in collected_tool_calls if tc.get("id")]

        # Store thinking content if any was collected and thinking display is enabled
        if self.show_thinking and collected_thinking:
            self._log(f"\n[THINKING SUMMARY]")
            self._log(collected_thinking)
            self._log("")

        final_response = {
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": collected_content if collected_content else None,
                    "tool_calls": final_tool_calls if final_tool_calls else None,
                    # Use reasoning_content so models like DeepSeek receive it back on the next request.
                    # The OpenAI-compatible API expects reasoning_content, not "thinking".
                    "reasoning_content": collected_thinking if collected_thinking else None
                }
            }]
        }
        return final_response

    def process_llm_response(self, response: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]], Optional[str], Optional[str], List[Dict[str, Any]]]:
        """Process LLM response and extract ALL tool calls, content, and thinking content.

        Returns:
            content: The text content of the response.
            tool_calls_info: A list of dicts, each with keys:
                - tool_call_id (str)
                - function_name (str)
                - arguments_str (str)
                - command (str or None)  -- populated for execute_bash
            first_tool_call_id: The id of the first tool call (for backward compat).
            thinking: The thinking/reasoning content if any.
            malformed_tool_calls: A list of dicts describing tool calls whose
                arguments could not be parsed as valid JSON. Each dict has:
                - tool_call_id (str)
                - function_name (str)
                - raw_arguments (str)
                - parse_error (str)
        """
        message = response["choices"][0]["message"]
        content = message.get("content")
        tool_calls = message.get("tool_calls")
        # Support both "reasoning_content" (OpenAI/DeepSeek standard) and "thinking" (legacy).
        thinking = message.get("reasoning_content") or message.get("thinking")

        tool_calls_info: List[Dict[str, Any]] = []
        first_tool_call_id = None
        malformed_tool_calls: List[Dict[str, Any]] = []

        if tool_calls:
            first_tool_call_id = tool_calls[0].get("id")
            for tool_call in tool_calls:
                tc_id = tool_call.get("id")
                function_name = tool_call.get("function", {}).get("name")
                arguments_str = tool_call.get("function", {}).get("arguments")

                command = None
                parsed_args = None
                parse_error = None

                if arguments_str:
                    try:
                        parsed_args = json.loads(arguments_str)
                    except json.JSONDecodeError as e:
                        parse_error = str(e)
                        self._log_error(f"[ERROR] Tool call arguments could not be parsed as JSON: {parse_error}")

                if parse_error is not None:
                    malformed_tool_calls.append({
                        "tool_call_id": tc_id,
                        "function_name": function_name,
                        "raw_arguments": arguments_str,
                        "parse_error": parse_error,
                    })
                    continue

                if function_name == "execute_bash" and parsed_args is not None:
                    command = parsed_args.get("command")

                tool_calls_info.append({
                    "tool_call_id": tc_id,
                    "function_name": function_name,
                    "function_arguments": arguments_str,
                    "command": command,
                })

        return content or "", tool_calls_info, first_tool_call_id, thinking, malformed_tool_calls

    def handle_function_call(self, function_info: Dict[str, Any]) -> str:
        """Handle different function calls"""
        function_name = function_info.get("name")
        arguments_str = function_info.get("arguments")

        if not arguments_str:
            return "No arguments provided for function call"

        try:
            args = json.loads(arguments_str)
        except json.JSONDecodeError as e:
            return (f"ERROR: The JSON arguments provided for function '{function_name}' "
                    f"could not be parsed. Parse error: {e}. "
                    f"Please re-issue this tool call with valid, properly formatted JSON "
                    f"arguments. Ensure all strings use double quotes, no literal newlines "
                    f"inside strings (use \\n), no trailing commas, and the entire "
                    f"argument is a single valid JSON object.")

        if function_name == "store_memory":
            return self.handle_store_memory(args)
        elif function_name == "retrieve_memories":
            return self.handle_retrieve_memories(args)
        elif function_name == "search_memories":
            return self.handle_search_memories(args)
        elif function_name == "delete_memory":
            return self.handle_delete_memory(args)
        else:
            return f"Unknown function: {function_name}"

    def run_interactor(self, user_request: str):
        """Main interactive loop"""
        self.sink.emit("SYSTEM", {
            "text": "[LLM INTERACTOR STARTED]",
            "api_base": self.base_url,
            "model": self.model,
            "auto_approve": self.auto_approve,
            "memory_enabled": self.memory_enabled,
            "max_prompt_len": self.max_prompt_len,
        })
        self._log(f"[USER REQUEST] {user_request}")
        self._log(f"{'='*60}")

        # Initialize conversation with system prompt and user request
        self.conversation_history = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": user_request}
        ]

        iteration = 0

        try:
            while iteration < self.max_iterations and not self.stop_event.is_set():

                if self.debug:
                    self._dump_conversation_history()

                iteration += 1
                self._log(f"\n[ITERATION {iteration}/{self.max_iterations}]")
                self.sink.emit("STATUS_UPDATE", {"iteration": iteration, "max_iterations": self.max_iterations, "phase": "llm_call"})

                # Truncate conversation history if it exceeds max_prompt_len
                self._truncate_conversation_history()

                response = self.call_llm_api(list(self.conversation_history))

                # Check if this is a safety-stop response (empty validated messages)
                if not response.get("choices") or not response.get("choices", [{}])[0].get("message"):
                    self._log(f"\n[SAFETY STOP] API call returned no valid response. Ending interaction.")
                    break

                assistant_message = response["choices"][0]["message"]

                # Check if this is a terminal safety response from _validate_messages
                _content_raw = assistant_message.get("content") or ""
                if (_content_raw.strip().endswith(self.COMPLETION_MARKER) and
                    not assistant_message.get("tool_calls") and
                    not assistant_message.get("reasoning_content") and
                    len(_content_raw) < 200):
                    self._log(f"\n[SAFETY STOP - TERMINAL] Terminal state reached. Ending interaction safely.")
                    break

                # Remove reasoning_content from the stored message to avoid
                # confusing APIs that don't expect it in subsequent requests
                clean_message = dict(assistant_message)
                clean_message.pop("reasoning_content", None)

                # Do NOT append if it would create consecutive assistant messages
                # (this should not happen due to validation, but double-check)
                if self.conversation_history and self.conversation_history[-1].get("role") == "assistant":
                    # Replace the previous assistant message instead of adding a new one
                    self.conversation_history[-1] = clean_message
                else:
                    self.conversation_history.append(clean_message)
                content, tool_calls_info, first_tool_call_id, thinking, malformed_tool_calls = self.process_llm_response(response)


                self._log(f"\n[LLM RESPONSE]")
                self._log(content)

                # Store conversation in memory if enabled
                if self.memory_manager:
                    # Store both content and thinking if available
                    full_content = content
                    if thinking:
                        full_content = f"THINKING: {thinking}\n\nRESPONSE: {content}"
                    self.memory_manager.store_conversation(self.session_id, "assistant", full_content)

                # Handle malformed tool calls - notify the LLM and request a corrected response
                if malformed_tool_calls:
                    self._log(f"[INFO] {len(malformed_tool_calls)} tool call(s) had malformed JSON arguments. Requesting correction from LLM.")
                    for mal in malformed_tool_calls:
                        err_msg = (
                            f"ERROR: The tool call with id '{mal['tool_call_id']}' (function: '{mal['function_name']}') "
                            f"contained malformed JSON arguments that could not be parsed.\n\n"
                            f"Parse error: {mal['parse_error']}\n\n"
                            f"Your function arguments MUST be a valid JSON object. Ensure:\n"
                            f"1. All strings are properly quoted with double quotes\n"
                            f"2. No unescaped newline characters inside strings (use \\n instead of literal newlines)\n"
                            f"3. No trailing commas\n"
                            f"4. The entire argument string is a single valid JSON object\n\n"
                            f"Please re-issue the tool call with corrected, valid JSON arguments. "
                            f"If you cannot produce valid JSON for this tool call, respond with a normal text message instead."
                        )
                        self.conversation_history.append({
                            "role": "tool",
                            "tool_call_id": mal["tool_call_id"],
                            "content": err_msg,
                        })
                    self._log(f"[INFO] Correction messages appended. Continuing to next iteration for LLM to fix the tool calls.")
                    # Do not proceed with normal tool execution this iteration; let the loop continue
                    # so the LLM can re-issue corrected tool calls.
                    continue

                # Execute ALL tool calls if any were provided
                if tool_calls_info:
                    self._log(f"[INFO] Executing {len(tool_calls_info)} tool call(s)...")

                    for idx, tc_info in enumerate(tool_calls_info):
                        if self.stop_event.is_set():
                            self._log("[STOP] Agent shutdown requested. Aborting tool execution.")
                            break
                        tool_call_id = tc_info["tool_call_id"]
                        command = tc_info.get("command")
                        function_name = tc_info.get("function_name")

                        if not command:
                            # Non-execute_bash tool call (memory functions); route to handle_function_call
                            self._log(f"[INFO] Tool call {idx+1}/{len(tool_calls_info)} has no command to execute (function={function_name}). Handling memory function call.")
                            if tool_call_id and function_name:
                                result = self.handle_function_call({"name": function_name, "arguments": tc_info["function_arguments"]})
                                self.conversation_history.append({
                                    "role": "tool",
                                    "tool_call_id": tool_call_id,
                                    "content": result
                                })
                            continue

                        self._log(f"[TOOL CALL {idx+1}/{len(tool_calls_info)}] {command}")

                        # Notify sink that a command is about to execute
                        self.sink.emit("CMD_EXEC", {"command": command, "tool_call_id": tool_call_id, "function_name": function_name})

                        approved, user_suggestion = self.get_user_confirmation(command)

                        if approved:
                            try:
                                output, exit_code = self.execute_bash_command(command)

                                if tool_call_id:
                                    self.conversation_history.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call_id,
                                        "content": f"Command executed with exit code {exit_code}.\nOutput:\n{output}"
                                    })

                                    # Store conversation in memory if enabled
                                    if self.memory_manager:
                                        self.memory_manager.store_conversation(self.session_id, "tool",
                                            f"Command: {command}\nExit: {exit_code}\nOutput: {output[:500]}...")

                            except CommandTimeoutError as e:
                                error_msg = str(e)
                                self._log_error(f"[TIMEOUT] {error_msg}")

                                if tool_call_id:
                                    self.conversation_history.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call_id,
                                        "content": error_msg
                                    })
                            except Exception as e:
                                error_msg = f"Command execution failed: {str(e)}"
                                self._log_error(f"[ERROR] {error_msg}")

                                if tool_call_id:
                                    self.conversation_history.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call_id,
                                        "content": error_msg
                                    })
                        else:
                            self._log(f"[INFO] Command not approved by user.")

                            if tool_call_id:
                                self.conversation_history.append({
                                    "role": "tool",
                                    "tool_call_id": tool_call_id,
                                    "content": "Command execution skipped by user."
                                })

                                if user_suggestion:
                                    self.conversation_history.append({
                                        "role": "user",
                                        "content": f"I suggest you {user_suggestion}"
                                    })
                else:
                    self._log(f"[INFO] No tool calls to execute in this iteration")
                    _content_check = content if isinstance(content, str) else ""

                    if _content_check.strip().endswith(self.COMPLETION_MARKER) or self.COMPLETION_MARKER in _content_check:
                        # The assistant has signaled task completion
                        break

                    # The assistant stopped without calling tools and without signaling
                    # completion.  This is a premature stop - the task is NOT finished.
                    # Inject a continuation message so the LLM keeps working until done.
                    self._log(f"[CONTINUATION] Assistant provided a response without tool calls and without completion signal. Task is not finished. Injecting continuation prompt.")

                    continuation_msg = (
                        f"Continue working on the task. You previously responded without using any tools. "
                        f"If the task is truly complete, you MUST emit the completion signal \"{self.COMPLETION_MARKER}\" "
                        f"on its own. Otherwise, continue by using the appropriate tools to make progress. "
                        f"Do NOT simply describe what needs to be done - take the next concrete step using "
                        f"execute_bash or other available tools. Remember: you must keep going until the "
                        f"task is fully finished, then emit \"{self.COMPLETION_MARKER}\"."
                    )
                    self.conversation_history.append({"role": "user", "content": continuation_msg})
                    # Continue the loop - do NOT break

                # Check for task completion AFTER command execution
                if self.COMPLETION_MARKER in content:
                    self._log(f"\n[{self.COMPLETION_MARKER} DETECTED - TASK COMPLETED SUCCESSFULLY]")
                    break

                # Check if we've reached max iterations
                if iteration >= self.max_iterations:
                    self._log(f"[LIMIT REACHED] Maximum iterations ({self.max_iterations}) exceeded")

        finally:
            self.sink.emit("SHUTDOWN", {"reason": "agent_loop_terminated"})

        self._log(f"\n{'='*60}")
        self._log(f"[INTERACTOR FINISHED]")

        # Clear any pending approval gate on shutdown
        if hasattr(self.sink, 'close'):
            self.sink.close()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Advanced LLM Interactor Tool with Enhanced Memory")
    parser.add_argument("--api-base", required=True, help="API base URL")
    parser.add_argument("--model", required=True, help="Model name")
    parser.add_argument("--api-key", required=True, help="API key")
    parser.add_argument("--auto-approve", action="store_true",
                        help="Auto-approve command execution (for testing)")
    parser.add_argument("--no-memory", action="store_true",
                        help="Disable memory system")
    parser.add_argument("--no-thinking", action="store_true",
                        help="Hide thinking tokens from output")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Command timeout in seconds (default: 30)")
    parser.add_argument("--max-prompt-len", type=int, default=80000,
                        help="Maximum prompt length in characters (default: 80000)")
    parser.add_argument("--max-output-bytes", type=int, default=10240,
                        help="Maximum output bytes to return from commands (default: 10240)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug mode (dump conversation history on truncation)")
    parser.add_argument("--nogui", action="store_true",
                        help="Run in direct CLI mode without TUI (original behaviour)")
    parser.add_argument("request", nargs="*", help="Task request")

    args = parser.parse_args()

    if not args.request:
        print("[ERROR] Please provide a task request", file=sys.stderr)
        sys.exit(1)

    # Determine sink mode: --nogui uses ConsoleSink (direct CLI, original behaviour).
    # Default (no flag) uses TUISink + Textual app.  The TUI path requires the
    # Textual library to be available.
    if args.nogui:
        sink = ConsoleSink()
        interactor = LLMInteractor(
            api_base=args.api_base,
            model=args.model,
            api_key=args.api_key,
            auto_approve=args.auto_approve,
            memory_enabled=not args.no_memory,
            show_thinking=not args.no_thinking,
            command_timeout=args.timeout,
            max_prompt_len=args.max_prompt_len,
            max_output_bytes=args.max_output_bytes,
            debug=args.debug,
            sink=sink
        )
        try:
            user_request = " ".join(args.request)
            interactor.run_interactor(user_request)
        except KeyboardInterrupt:
            interactor._log("\n[INTERRUPTED] Interactor stopped by user")
            sys.exit(0)
        except Exception as e:
            interactor._log_error(f"\n[FATAL ERROR] An unexpected error occurred:")
            import traceback
            tb_str = traceback.format_exc()
            interactor._log_error(tb_str)
            sys.exit(1)
        return

    # TUI mode
    if not _TEXTUAL_AVAILABLE:
        print("Textual library is not installed. Install it with: pip install textual")
        print("Alternatively, run with --nogui for direct CLI mode.")
        sys.exit(1)

    # Import Textual widgets (only available in TUI mode)
    from textual.app import App, ComposeResult
    from textual.widgets import RichLog, Input, Static
    from textual import events
    from textual.binding import Binding

    class InteractorApp(App):
        """Textual TUI for the LLM Interactor.

        Layout (4 regions):
            ┌────────────────────────────────┬───────────────────────────┐
            │  [1] Prompt Input (top-left)    │  [2] Console Log (top-right)
            │  - user prompt entry            │  - command output (live)
            │  - /autoapprove toggle          │  - exit codes
            ├────────────────────────────────┴───────────────────────────┤
            │  [3] Agent Output (bottom, full width)
            │  - LLM reasoning/thinking
            │  - LLM text responses
            │  - tool-call summaries
            ├────────────────────────────────────────────────────────────┐
            │  [4] Status Footer
            │  - model | tok/s | iterations | session id | auto-approve status
            └────────────────────────────────────────────────────────────┘

        The agent runs in a background thread and pushes events to a queue.
        The main thread polls the queue via set_interval(0.05) and renders
        events to widgets.  The agent thread NEVER touches widgets directly.
        """

        CSS = """
        Screen {
            background: #0a0a0a;
        }
        #warning-banner {
            background: #4a0000;
            color: #ff0000;
            padding: 1 2;
            border: solid #8b0000;
            margin-bottom: 1;
        }
        #prompt-container {
            background: #1a1a1a;
            border: solid #333333;
            padding: 1;
            margin-bottom: 1;
        }
        #prompt-input {
            background: #000000;
            color: #00ff00;
            border: solid #444444;
            padding: 0 2;
            width: 100%;
            height: 3;
        }
        #prompt-input:focus {
            border: tall #00aa00;
        }
        #prompt-input > .input--cursor {
            background: #00ff00;
            color: #000000;
        }
        #status-bar {
            background: #1a1a1a;
            color: #ff6600;
            padding: 1 2;
            border-top: solid #444444;
        }
        RichLog {
            border: solid #444444;
            padding: 0;
        }
        #console-log {
            background: #000000;
            color: #00ff00;
            border: solid #006600;
            margin-bottom: 1;
        }
        #agent-log {
            background: #000000;
            color: #00ffff;
            border: solid #440044;
            margin-bottom: 1;
        }
        """

        # Disable Textual's internal mouse-capture selection so the
        # terminal's native text-selection/copy works normally.  In most
        # terminals (xterm, gnome-terminal, kitty, iTerm2) this lets you
        # select and copy text the usual way (drag, or Shift+drag when
        # the terminal intercepts mouse events).  Textual's built-in
        # selection only populates an internal buffer that cannot be
        # pasted into external applications, so it is useless for real
        # copy/paste and only interferes with the terminal.
        ALLOW_SELECT = False

        def __init__(self, args):
            super().__init__()
            self.args = args
            self.event_queue: queue.Queue = queue.Queue()
            self.stop_event = threading.Event()
            self.agent_thread: Optional[threading.Thread] = None
            self.auto_approve = args.auto_approve
            self.iteration_count = 0
            self.max_iterations = 500
            self.tokens_per_second = 0.0
            # Token-rate tracking state.  We count streamed chunks (each is
            # roughly one token) and compute a rolling rate over a short
            # window so the status bar shows a live tok/s while the LLM is
            # streaming, and decays to 0.0 when it is not.
            self._tok_count = 0
            self._tok_window_start = time.monotonic()
            self._tok_window_tokens = 0
            self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.model_name = args.model
            self.api_base = args.api_base
            self.sink: TUISink = None
            self.agent = None
            self.pending_approval = None  # dict with 'command' awaiting user decision
            # Streaming buffers accumulate tokens per-widget so RichLog.write()
            # doesn't create one line per token.  Keys are widget ids.
            self._stream_buffer: Dict[str, str] = {}
            # Track which stream prefixes have already been displayed so a
            # label like "[THINKING]" is shown once at the start of a stream
            # rather than prepended to every token chunk.
            self._stream_prefix_done: set = set()

        def compose(self) -> ComposeResult:
            # Warning banner at top
            yield Static(
                "⚠ AGENT WILL EXECUTE REAL BASH COMMANDS ON THIS SYSTEM ⚠\n"
                "Auto-approve is OFF. Every command requires /approve or /reject.\n"
                "Type /autoapprove (or /aa) to toggle auto-approve for this session.\n"
                "───────────────────────────────────────────────────────────────────\n"
                "COPY/PASTE: Text selection is handled by your TERMINAL, not this app.\n"
                "  • Most terminals: drag to select, then middle-click or Ctrl+Shift+C/V\n"
                "  • If mouse is captured: hold SHIFT while dragging to bypass app capture\n"
                "  • This app has disabled its own mouse capture to allow native selection",
                id="warning-banner",
                markup=False
            )
            # Prompt input field (top-left)
            yield Input(id="prompt-input", placeholder="Type a prompt or /command, then Enter")
            # Console output panel (top-right) - RichLog for streaming command output
            console = RichLog(id="console-log", auto_scroll=True, wrap=True, max_lines=1000)
            console.border_title = "Console Output"
            yield console
            # Agent output panel (bottom, full width) - RichLog for streaming LLM output
            agent = RichLog(id="agent-log", auto_scroll=True, wrap=True, max_lines=2000)
            agent.border_title = "Agent Output"
            yield agent
            # Status footer
            yield Static(id="status-bar")

        def on_mount(self):
            self.title = "LLM Interactor TUI"
            self.sub_title = f"Model: {self.model_name} | Session: {self.session_id}"
            self.update_status_bar()
            # Give keyboard focus to the prompt input so typed commands are
            # captured immediately instead of going nowhere.
            try:
                self.query_one("#prompt-input").focus()
            except Exception:
                pass
            # Poll the event queue every 50 ms
            self.set_interval(0.05, self._drain_queue)

            # If a task request was supplied on the command line, auto-start
            # the agent with it instead of discarding it.  This mirrors the
            # --nogui path where args.request is passed straight to
            # run_interactor().  We schedule via a one-shot callback so the
            # app has finished composing widgets before we start the
            # background thread; the request is consumed so a remount
            # (e.g. resize) does not re-launch.
            cli_request = " ".join(self.args.request) if self.args.request else ""
            self.args.request = []
            if cli_request.strip():
                self._write_agent(
                    f"[CLI REQUEST] Auto-starting agent with the request supplied on the command line:\n  {cli_request[:200]}"
                )
                self._cli_request = cli_request
                self.set_timer(0.5, self._autostart_once)

        def update_status_bar(self):
            sb = self.query_one("#status-bar")
            ap_status = "ON" if self.auto_approve else "OFF"
            status_text = (
                f"Model: {self.model_name} | "
                f"Iter: {self.iteration_count}/{self.max_iterations} | "
                f"tok/s: {self.tokens_per_second:.1f} | "
                f"Session: {self.session_id} | "
                f"Auto-approve: {ap_status} | "
                f"Pending approval: {'YES' if self.pending_approval else 'no'}"
            )
            sb.update(status_text)

        def _drain_queue(self):
            """Poll the event queue and dispatch events to widgets.  Runs on
            the main Textual thread; the agent thread only writes to the
            queue, never touches widgets."""
            # Drain up to 200 events per tick to avoid starving the UI
            for _ in range(200):
                if self.event_queue.empty():
                    break
                try:
                    event = self.event_queue.get_nowait()
                except queue.Empty:
                    break
                self._dispatch_event(event)

            # If agent thread has exited, clean up
            if self.agent_thread and not self.agent_thread.is_alive():
                self._handle_agent_exit()

            self.update_status_bar()

        def _dispatch_event(self, event: dict):
            kind = event.get("kind", "")
            payload = event.get("payload", {})

            if kind == "SYSTEM":
                self._write_agent("[SYSTEM] " + payload.get('text',''), style="bold blue")
                self._write_agent(f"  API: {payload.get('api_base','')}", style="blue")
                self._write_agent(f"  Model: {payload.get('model','')}", style="blue")
                self._write_agent(f"  Auto-approve: {payload.get('auto_approve', False)}", style="blue")
                self._write_agent(f"  Memory: {payload.get('memory_enabled', False)}", style="blue")
                self._write_agent(f"  Max prompt len: {payload.get('max_prompt_len', 0)}", style="blue")
                self._write_agent("  [!] Agent starting. Commands will require approval unless /autoapprove is toggled.", style="yellow")
            elif kind == "LOG":
                self._write_agent(payload.get("text", ""))
            elif kind == "ERROR":
                self._write_agent(f"[ERROR] {payload.get('text', '')}", style="bold red")
            elif kind == "LLM_STREAM":
                self._write_agent(payload.get("text", ""), streaming=True, style="cyan")
                self._track_token()
            elif kind == "THINKING_STREAM":
                self._write_agent(payload.get("text", ""), streaming=True, prefix="[THINKING] ", style="magenta")
                self._track_token()
            elif kind == "CMD_EXEC":
                cmd = payload.get("command", "")
                tcid = payload.get("tool_call_id", "")
                fn = payload.get("function_name", "")
                self._write_console(f"[COMMAND REQUESTED] {cmd}", style="bold yellow")
                self._write_console(f"  tool_call_id: {tcid}  function: {fn}", style="yellow")
                self._write_console(f"  ⚠ This command will execute when approved.", style="yellow")
                # Set pending approval state
                self.pending_approval = {"command": cmd, "tool_call_id": tcid}
                self._refresh_approval_prompt()
            elif kind == "APPROVAL_REQUEST":
                cmd = payload.get("command", "")
                self.pending_approval = {"command": cmd}
                self._write_console(f"\n[APPROVAL REQUIRED] Command: {cmd}", style="bold yellow")
                self._write_console(f"  Type /approve to execute, /reject to deny, or /suggest <text> to provide guidance.", style="yellow")
                self._refresh_approval_prompt()
            elif kind == "CMD_OUTPUT":
                text = payload.get("text", "")
                cmd = payload.get("command", "")
                self._write_console(text, style="green")
            elif kind == "CMD_COMPLETE":
                cmd = payload.get("command", "")
                exit_code = payload.get("exit_code", -1)
                output = payload.get("output", "")
                self._write_console(f"[COMMAND COMPLETE] {cmd}", style="bold green")
                self._write_console(f"  Exit code: {exit_code}", style="green")
                if output:
                    self._write_console(f"  Output:\n{output}", style="green")
                self.pending_approval = None
                self._refresh_approval_prompt()
            elif kind == "STATUS_UPDATE":
                self.iteration_count = payload.get("iteration", 0)
                self.max_iterations = payload.get("max_iterations", 500)
                # If no tokens have streamed recently, decay the displayed
                # rate so it doesn't show a stale value while the agent is
                # running commands or waiting on approval.
                self._decay_token_rate()
            elif kind == "SHUTDOWN":
                self._write_agent("[SHUTDOWN] Agent loop terminated.", style="bold red")
                self._handle_agent_exit()

            self.update_status_bar()

        def _track_token(self):
            """Record that a token chunk arrived and update the rolling rate.

            Uses a short sliding window so the displayed tok/s reflects the
            current streaming speed rather than the session average.
            """
            now = time.monotonic()
            self._tok_count += 1
            self._tok_window_tokens += 1
            # Roll the window every ~1s.
            if now - self._tok_window_start >= 1.0:
                elapsed = now - self._tok_window_start
                if elapsed > 0:
                    self.tokens_per_second = self._tok_window_tokens / elapsed
                self._tok_window_start = now
                self._tok_window_tokens = 0

        def _decay_token_rate(self):
            """Reset the displayed rate to 0 once streaming has been idle
            for more than 2 seconds (e.g. between tool calls)."""
            if self._tok_window_tokens == 0 and time.monotonic() - self._tok_window_start >= 2.0:
                self.tokens_per_second = 0.0

        def _write_agent(self, text: str, streaming: bool = False, prefix: str = "", style: str = ""):
            """Write text to the agent output RichLog (bottom panel).

            When *streaming* is True (LLM/Thinking tokens) the text is
            accumulated in a buffer and flushed as complete lines, so tokens
            flow inline instead of one-per-line.  This avoids touching
            RichLog's private internal storage (which is fragile across
            Textual versions); the partial (incomplete) line is held in the
            buffer and written out once a newline arrives or the stream ends.

            A *prefix* label (e.g. "[THINKING]") is shown ONCE at the start
            of a stream session, never prepended to individual token chunks.

            *style* is a Rich style string (e.g. "bold red", "cyan").
            """
            try:
                from rich.text import Text
                widget = self.query_one("#agent-log")
                clean = _strip_ansi(text)
                buf_key = "#agent-log"
                # --- Streaming path -------------------------------------------------
                if streaming:
                    # On the very first chunk of a new stream, emit the label
                    # once as its own line, then mark it done so it is never
                    # prepended to subsequent token chunks.
                    if prefix and buf_key not in self._stream_prefix_done:
                        self._stream_prefix_done.add(buf_key)
                        label = Text(_strip_ansi(prefix).strip(), style=style or "magenta")
                        widget.write(label)

                    # Accumulate the CLEAN token text (no prefix) into the buffer.
                    buf = self._stream_buffer.get(buf_key, "") + clean
                    # Split on newlines: flush complete lines, keep the remainder
                    # (the still-growing current line) buffered until it completes.
                    parts = buf.split("\n")
                    remainder = parts[-1]
                    self._stream_buffer[buf_key] = remainder
                    for part in parts[:-1]:
                        styled = Text(part, style=style) if style else Text(part)
                        widget.write(styled)
                # --- Non-streaming path (stream ended or normal message) -----------
                else:
                    # A non-streaming write signals the end of any active
                    # stream.  First flush whatever is pending in the buffer,
                    # then reset stream-tracking state so the next stream
                    # starts fresh.
                    pending = self._stream_buffer.pop(buf_key, "")
                    if pending:
                        styled = Text(pending, style=style) if style else Text(pending)
                        widget.write(styled)
                    self._stream_prefix_done.discard(buf_key)

                    full = _strip_ansi(prefix) + clean
                    styled = Text(full, style=style) if style else Text(full)
                    widget.write(styled)
            except Exception:
                pass

        def _write_console(self, text: str, style: str = ""):
            """Write text to the console output RichLog (top-right panel).

            *style* is a Rich style string (e.g. "bold red", "green").
            """
            try:
                from rich.text import Text
                widget = self.query_one("#console-log")
                clean = _strip_ansi(text)
                if style:
                    styled = Text(clean, style=style)
                else:
                    styled = Text(clean)
                widget.write(styled)
            except Exception:
                pass

        def _refresh_approval_prompt(self):
            """Update the warning banner to show pending approval status."""
            try:
                banner = self.query_one("#warning-banner")
                if self.pending_approval:
                    status = (
                        "⚠ PENDING APPROVAL ⚠\n"
                        f"  Command: {self.pending_approval.get('command','')}\n"
                        "  Type /approve to execute, /reject to deny, or /suggest <text> for guidance\n"
                        "  Agent is BLOCKED waiting for your decision."
                    )
                else:
                    status = (
                        "⚠ AGENT WILL EXECUTE REAL BASH COMMANDS ON THIS SYSTEM ⚠\n"
                        "Auto-approve is OFF. Every command requires /approve or /reject.\n"
                        "Type /autoapprove (or /aa) to toggle auto-approve for this session."
                    )
                banner.update(status)
            except Exception:
                pass

        def _handle_agent_exit(self):
            """Called when the agent thread finishes (normally or via stop)."""
            self.stop_event.set()
            self.agent_thread = None
            self.agent = None
            self.pending_approval = None
            self._write_agent("[AGENT EXITED] Cleaning up...")
            # Do not close the app automatically; let user review output.
            self._refresh_approval_prompt()
            self.update_status_bar()

        def _autostart_once(self):
            """One-shot dispatcher used by on_mount to launch the agent with
            a command-line supplied request.  Cancels itself after firing."""
            try:
                prompt = getattr(self, "_cli_request", "")
                if prompt:
                    self._start_agent(prompt)
            except Exception as exc:
                self._write_agent(f"[ERROR] Failed to auto-start from CLI request: {exc}")
            finally:
                return False  # returning False cancels the recurring interval

        def _start_agent(self, prompt: str):
            """Start the agent thread with the given prompt."""
            if self.agent_thread and self.agent_thread.is_alive():
                self._write_agent("[ERROR] Agent is already running.")
                return
            # Clear the stop event so the new agent run starts fresh.
            self.stop_event.clear()
            self.sink = TUISink(self.event_queue, self.stop_event)
            self.sink.auto_approve = self.auto_approve
            self.agent = LLMInteractor(
                api_base=self.api_base,
                model=self.model_name,
                api_key=self.args.api_key,
                auto_approve=self.auto_approve,
                memory_enabled=not self.args.no_memory,
                show_thinking=not self.args.no_thinking,
                command_timeout=self.args.timeout,
                max_prompt_len=self.args.max_prompt_len,
                max_output_bytes=self.args.max_output_bytes,
                debug=self.args.debug,
                sink=self.sink
            )
            self.agent_thread = threading.Thread(
                target=self.agent.run_interactor,
                args=(prompt,),
                daemon=True
            )
            self.agent_thread.start()
            self._write_agent(f"[AGENT STARTED] Processing: {prompt[:80]}...")

        def _stop_agent(self):
            """Stop the agent thread cleanly."""
            if self.agent:
                self.agent.stop_event.set()
            self.stop_event.set()
            if self.agent_thread and self.agent_thread.is_alive():
                self._write_agent("[STOP] Signal sent. Waiting for agent to exit (up to 5s)...")
                self.agent_thread.join(timeout=5)
            self.pending_approval = None
            self._refresh_approval_prompt()

        # --- Input handling ---
        # The Input widget emits Input.Submitted events when the user presses
        # Enter.  We intercept the text to handle slash commands and prompt
        # submission.  The input field is in the prompt panel.

        def on_input_submitted(self, event):
            """Handle Enter key in the prompt input field."""
            text = event.value.strip()
            # Clear the input field
            try:
                input_widget = self.query_one("#prompt-input")
                input_widget.value = ""
            except Exception:
                pass

            if not text:
                return

            # Slash commands
            if text.startswith("/"):
                self._handle_slash_command(text)
                return

            # Otherwise, treat as a prompt to start the agent
            self._start_agent(text)

        def _handle_slash_command(self, cmd: str):
            """Handle slash commands typed in the prompt panel."""
            cmd_lower = cmd.lower()
            parts = cmd_lower.split(" ", 1)
            command = parts[0]
            arg = parts[1] if len(parts) > 1 else ""

            if command in ("/autoapprove", "/aa"):
                self.auto_approve = not self.auto_approve
                if self.sink:
                    self.sink.auto_approve = self.auto_approve
                self._write_agent(
                    f"[AUTO-APPROVE TOGGLED] auto_approve is now "
                    f"{'ON (commands will run without asking)' if self.auto_approve else 'OFF (commands will require /approve)'}"
                )
                if self.auto_approve:
                    self._write_agent(
                        "  ⚠ WARNING: All commands will execute automatically without approval.\n"
                        "  ⚠ Ensure you are monitoring the console panel and can /stop if needed."
                    )
                self.update_status_bar()

            elif command == "/approve":
                if not self.pending_approval:
                    self._write_agent("[ERROR] No pending approval to approve.")
                    return
                if self.sink and self.sink._approval_event:
                    self.sink.resolve_approval(approved=True)
                    self._write_console(f"[APPROVED] {self.pending_approval.get('command','')}")
                else:
                    self._write_agent("[ERROR] No active approval gate to resolve.")
                self.pending_approval = None
                self._refresh_approval_prompt()

            elif command == "/reject":
                if not self.pending_approval:
                    self._write_agent("[ERROR] No pending approval to reject.")
                    return
                if self.sink and self.sink._approval_event:
                    self.sink.resolve_approval(approved=False)
                    self._write_console(f"[REJECTED] {self.pending_approval.get('command','')}")
                else:
                    self._write_agent("[ERROR] No active approval gate to resolve.")
                self.pending_approval = None
                self._refresh_approval_prompt()

            elif command == "/suggest":
                if not self.pending_approval:
                    self._write_agent("[ERROR] No pending approval to suggest for.")
                    return
                if self.sink and self.sink._approval_event:
                    self.sink.resolve_approval(approved=False, suggestion=arg)
                    self._write_console(f"[REJECTED WITH SUGGESTION] {self.pending_approval.get('command','')}")
                else:
                    self._write_agent("[ERROR] No active approval gate to resolve.")
                self.pending_approval = None
                self._refresh_approval_prompt()

            elif command == "/stop":
                self._write_agent("[STOP] Stopping agent...")
                self._stop_agent()

            else:
                self._write_agent(f"[UNKNOWN COMMAND] {cmd}")
                self._write_agent("Available: /autoapprove /aa /approve /reject /suggest /stop")

        # --- Key bindings ---
        def key_press(self, event):
            """Handle global key presses."""
            # Ctrl+C stops the agent and quits
            if event.key == "ctrl+c":
                self._stop_agent()
                self.shutdown()
                return
            # Escape also stops
            if event.key == "escape":
                self._stop_agent()
                self.shutdown()
                return

        def shutdown(self):
            """Clean shutdown: stop agent, close sink, exit app."""
            self._stop_agent()
            if self.sink:
                self.sink.close()
            # Remove the input widget if present
            try:
                input_widget = self.query_one("#prompt-input")
                input_widget.remove()
            except Exception:
                pass
            self.exit()

    # Instantiate and run the TUI
    app = InteractorApp(args)
    try:
        app.run()
    except KeyboardInterrupt:
        app._stop_agent()
        sys.exit(0)
    except Exception as e:
        print(f"[FATAL ERROR] TUI crashed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
