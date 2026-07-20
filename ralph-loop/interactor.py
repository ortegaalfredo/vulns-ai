#!/usr/bin/env python3
"""
Advanced LLM Interactor Tool with Enhanced Memory System
A sophisticated command-line tool that provides shell access and task planning 
capabilities to Large Language Models through function calling, with persistent 
memory using SQLite and text file storage.
"""

import argparse
import json
import subprocess
import sys
import time
from typing import Dict, List, Any, Optional, Tuple
import signal
import os
import pty
import select
from datetime import datetime
from openai import OpenAI
import sqlite3
from pathlib import Path

# Color codes for output
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
                  max_prompt_len: int = 20000, max_output_bytes: int = 10240, debug: bool = False):
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
        """Print to stdout"""
        print(message, end=end, flush=flush)
    
    def _log_error(self, message: str):
        """Print error to stderr"""
        print(message, file=sys.stderr)
    
    # --- Single-source-of-truth constants ---
    # The task-completion marker.  All logic that needs to detect or emit the
    # end-of-task signal references THIS constant instead of hard-coding the
    # string in multiple places.  Change it here and every reference updates.
    COMPLETION_MARKER = "TASKCOMPLETE"

    # The literal string injected by execute_bash_command() when output is
    # truncated at max_output_bytes.  Centralised here so the prompt can
    # reference the exact sentinel the runtime uses.
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
        self._log(f"{colors.YELLOW}[DEBUG DUMP]{colors.END} Conversation history dumped to interactor-debug.txt")

    def _truncate_conversation_history(self):
        """Truncate conversation history if it exceeds max_prompt_len.

        Removes oldest messages from conversation history, keeping the first user message
        (original instruction) and the most recent messages to maintain context.
        Removes in pairs (user+assistant) from oldest to newest.
        """
        # Calculate total prompt length
        total_len = sum(self._get_message_length(msg) for msg in self.conversation_history)

        if total_len <= self.max_prompt_len:
            return

        self._log(f"{colors.YELLOW}[TRUNCATING]{colors.END} Prompt length ({total_len}) exceeds max ({self.max_prompt_len}). Truncating conversation history.")
        
        # Keep first message (system prompt) and second message (first user instruction)
        # Remove from the middle/oldest messages, keeping recent context
        # Strategy: remove from position 2 onwards (after system + first user), oldest first
        
        # Build a list of removable indices (skip system at 0 and first user at 1)
        removable_indices = list(range(4, len(self.conversation_history)))
        
        # Remove from position 2 onwards (after system + first user), oldest first
        for idx in removable_indices:
            # Check if we need to truncate more
            current_len = sum(self._get_message_length(msg) for msg in self.conversation_history)
            if current_len <= self.max_prompt_len:
                break
            removed_msg = self.conversation_history[idx]
            removed_len = self._get_message_length(removed_msg)
            # Only replace tool output messages with condensed placeholder
            if removed_msg.get('role') == 'tool':
                if len(removed_msg['content'])>30: # If tool output is too long, remove it
                    removed_msg['content'] = '<condensed tool output>'
                    current_len = sum(self._get_message_length(msg) for msg in self.conversation_history)
                    self._log(f"{colors.YELLOW}[TRUNCATED]{colors.END} Removed {removed_msg.get('role')} message (removed {removed_len} chars, new length: {current_len})")
        
        final_len = sum(self._get_message_length(msg) for msg in self.conversation_history)
        self._log(f"{colors.YELLOW}[TRUNCATING COMPLETE]{colors.END} Final prompt length: {final_len}")
    
    def get_system_prompt(self) -> str:
        """Get the enhanced system prompt for the LLM with memory instructions"""
        marker = self.COMPLETION_MARKER
        truncation_sentinel = self.OUTPUT_TRUNCATION_SENTINEL
        timeout_seconds = self.command_timeout
        output_limit = self.max_output_bytes

        base_prompt = f"""You are an expert planning and execution assistant. Your goal is to fulfill the user's request by breaking it down into a series of manageable steps. You can execute bash commands to interact with the system.

**Workflow:**
1. **Analyze & Plan:** When you receive a user request, first analyze it. If it's complex, break it down into a list of tasks or steps. 
2. **TODO List**: Clearly state your plan EVERY 5 STEPS, and maintain a task list. For example: 'My plan is: 1. Do X, 2. Do Y, 3. Do Z.' write this list every time you finish a step or need to modify it to accomplish the goal.
3. **Execute:** Use the execute_bash tool to perform one step of your plan. Wait for the result of the command before proceeding
4. **Evaluate & Decide:** After receiving the result of a command, evaluate it. decide on the next step:
   - If there are more steps in your plan, execute the next one.
   - If a step failed or requires a different approach, adjust your plan and explain
   - If all steps are complete and the user's request is fulfilled, explicitly state that the **'{marker}'**.
5. **Task Completion:** Only conclude the conversation by stating '{marker}' when you are certain that all necessary actions have been taken and the user's goal has been achieved. Do not say this prematurely.

**IMPORTANT - COMMAND EXECUTION ENVIRONMENT & LIMITATIONS:**
You MUST be aware of the following runtime constraints when using execute_bash. Plan accordingly to avoid losing data or wasting iterations:

- **Output Truncation:** Command output is capped at {output_limit} bytes. If a command produces more output than this limit, the output will be cut short and the literal sentinel string `{truncation_sentinel}` will be appended to indicate truncation. This means:
  - You will NOT see the full output of commands that produce large amounts of data (e.g., recursive directory listings, large file reads, verbose builds).
  - If you see `{truncation_sentinel}` at the end of tool output, the output was truncated and you are missing data. Do NOT assume the command succeeded fully or failed based on partial output.
  - To handle truncation safely: pipe output through `head -c N` or `tail -c N` to retrieve specific portions. Use `--no-pager` flags where applicable (e.g., `git --no-pager log`). Redirect large outputs to a file and read them in chunks with `sed -n 'start,end p' /path/to/file`.
  - Prefer targeted commands (e.g., `grep pattern file`, `wc -l`, `stat file`) over dumping entire directories or files.

- **Command Timeout:** Commands are killed after {timeout_seconds} seconds. Long-running processes (e.g., compilation, network operations, large downloads) may be terminated before completion. For long operations:
  - Run them in the background with `nohup ... &` and check results later, OR
  - Break them into smaller steps, OR
  - Use `timeout` subcommands to set your own lower timeout to detect hangs early.

- **PTY Environment:** Commands execute in a pseudo-terminal (PTY). Some programs behave differently under PTY (e.g., colored output, interactive prompts). Use non-interactive flags (e.g., `-y`, `--no-interactive`) when available.

**IMPORTANT - Command Execution Results:**
- NEVER include command execution results (like "Command executed with exit code X" or "[EXECUTING] command" or "[COMPLETED] Command finished") in your response content.
- When you use execute_bash, the actual command output will be provided to you automatically by the tool system in subsequent turns.
- Your content should ONLY describe what you plan to do next or what you concluded from the actual results provided by the tool system.
- After a tool call, think and write your reasoning and any important information that you can infer from the tool output
- Do NOT fabricate, guess, or hallucinate command outputs. Wait for the real output from the tool system.

**Additional Guidelines:**
- Focus on one command at a time.
- Keep track of what you have done and what remains to be done in your task list.
- If you need up-to-date information from the internet, you can use the `ddgr` (duck-duck-go search), wget/curl and the w3m command-line browser to access sites (e.g. `ddgr --json --unsafe --np "your_query"`).

**CRITICAL — PERSISTENCE AND CONTINUATION POLICY:**
You MUST continue working until the task is genuinely complete. Do NOT stop early.
- If you respond without calling any tools, the system will inject a continuation prompt because the task is not finished. You are REQUIRED to keep making progress by calling tools (execute_bash, store_memory, retrieve_memories, search_memories, etc.) until every part of the task is done.
- Never produce a "final response" that only summarizes what should be done - instead, DO it. Use the tools to take concrete action.
- If you encounter an error, troubleshoot it. If a command fails, try alternative approaches. Iterate until the objective is achieved.
- The ONLY acceptable way to stop is to emit the exact phrase '{marker}' AFTER you have verified that all task objectives are met by actually executing the necessary commands and inspecting their results.
- If you are unsure whether the task is complete, it is NOT complete - continue working.
- Partial completion is NOT completion. Every item in your task list must be verified done through actual command execution before you emit '{marker}'.
- Do NOT ask the user for clarification mid-task unless you have exhausted all possible autonomous approaches.
- Before emitting '{marker}', verify the outcome of your last actions by running verification commands (e.g., checking file contents, running tests, confirming services are operational).

**ANTI-TRUNCATION SAFETY:**
When you receive output ending with `{truncation_sentinel}`, the output was cut short. You MUST re-run the command with output redirected to a file and read it in chunks with `sed -n 'start,end p' /path/to/file`, or use `head`/`tail` to get specific portions. Do NOT proceed based on truncated output.

Please think carefully, as the quality of your response is of the highest priority. You have unlimited thinking tokens for this."""
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
        self._log(f"\n{colors.YELLOW}[EXECUTING]{colors.END} {colors.BOLD}{command}{colors.END}")

        output_buffer = bytearray()
        
        try:
            import fcntl
        except ImportError:
            self._log_error(f"{colors.RED}[ERROR]{colors.END} 'fcntl' module not available. This PTY-based interactor requires a Unix-like system.")
            return "fcntl module not available", 1

        pid, master_fd = pty.fork()

        if pid == 0:
            # Best-effort: start a new process group so os.killpg(pid, ...) targets
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
        stdin_fl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        
        fcntl.fcntl(master_fd, fcntl.F_SETFL, master_fl | os.O_NONBLOCK)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, stdin_fl | os.O_NONBLOCK)

        # Derive the output kill threshold from the configurable max_output_bytes
        # (5x the limit) instead of a hardcoded 50KB, so the two stay in sync.
        output_kill_threshold = 5 * self.max_output_bytes

        start_time = time.time()
        try:
            while True:
                if time.time() - start_time > self.command_timeout:
                    self._log_error(f"{colors.RED}[TIMEOUT]{colors.END} Command timed out after {self.command_timeout} seconds. Sending SIGTERM.")
                    os.killpg(pid, signal.SIGTERM)
                    time.sleep(0.5)
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except OSError:
                        pass
                    timed_out = True
                    break

                rlist, _, _ = select.select([master_fd, sys.stdin.fileno()], [], [], 0.1)

                if master_fd in rlist:
                    try:
                        data = os.read(master_fd, 1024)
                        if data:
                            output_buffer.extend(data)
                            if len(output_buffer) > output_kill_threshold:
                                self._log_error(f"{colors.RED}[OUTPUT LIMIT]{colors.END} Command output exceeded {output_kill_threshold} bytes. Stopping command.")
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
                
                if sys.stdin.fileno() in rlist:
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

            # fcntl was imported successfully at the top of this function; ImportError
            # cannot occur here, so only catch OSError/AttributeError.
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
        
        # Log command completion with output and exit code
        self._log(f"\n{colors.GREEN}[COMPLETED]{colors.END} Command finished with exit code {exit_code}")
        if final_output.strip():
            self._log(f"{colors.CYAN}--- Command Output ---{colors.END}")
            self._log(final_output)
            self._log(f"{colors.CYAN}--- End Output ---{colors.END}")
        
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
        """Get user confirmation for command execution"""
        if self.auto_approve:
            self._log(f"{colors.GREEN}[AUTO-APPROVED]{colors.END} {command}")
            return True, None
            
        while True:
            self._log(f"\n{colors.MAGENTA}[CONFIRMATION REQUIRED]{colors.END}")
            self._log(f"Command to execute: {colors.BOLD}{command}{colors.END}")
            try:
                response_input = input(f"{colors.CYAN}Approve command? (y/n/suggestion): {colors.END}").strip().lower()
            except EOFError:
                # stdin closed (non-interactive use without --auto-approve); default to reject
                self._log_error(f"{colors.YELLOW}[INFO]{colors.END} stdin closed; rejecting command by default.")
                return False, None
            
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
            self._log(f"\n{colors.YELLOW}[SAFETY STOP]{colors.END} Conversation history validation returned empty - terminal assistant state detected. Ending interaction.")
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
        
        if self.model.find("gpt")==-1: # OpenAI don't like this
            request_params = {
                "model": self.model,
                "messages": messages,
                "temperature": 1.0,
                "stream": True,
                "max_tokens": self.max_tokens,
            }
            request_params['extra_body'] = {"chat_template_kwargs": {"enable_thinking": True}}
        else:
            request_params = {
                "model": self.model,
                "messages": messages,
                "temperature": 1.0,
                "stream": True,
                }

        if use_tools:
            request_params["tools"] = self.tool_schemas
            request_params["tool_choice"] = "auto"

        max_retries = 5
        wait_seconds = 60
        
        for attempt in range(1, max_retries + 1):
            try:
                self._log(f"\n{colors.WHITE}[LLM STREAMING RESPONSE]{colors.END} ", end="", flush=True)
                
                collected_content = ""
                collected_thinking = ""
                collected_tool_calls = []
                in_thinking = False
                thinking_buffer = ""

                stream = self.client.chat.completions.create(**request_params)
                
                for chunk in stream:
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

                                # Print thinking tokens in real-time with different color
                                print(f"{colors.MAGENTA}{reasoning_chunk}{colors.END}", end="", flush=True)
                                in_thinking = True
                            
                            # Handle regular content
                            if delta.content:
                                content_chunk = delta.content
                                collected_content += content_chunk
                                
                                # If we were in thinking mode, show transition
                                if self.show_thinking and in_thinking and thinking_buffer:
                                    self._log(f"\n{colors.CYAN}[THINKING COMPLETE]{colors.END}")
                                    in_thinking = False
                                
                                print(content_chunk, end="", flush=True)

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
                    self._log(f"{colors.YELLOW}[API ERROR] Connection error: {str(e)}. Retrying in {wait_seconds}s... (attempt {attempt}/{max_retries}){colors.END}")
                    time.sleep(wait_seconds)
                else:
                    raise
                continue

        self._log("")
        final_tool_calls = [tc for tc in collected_tool_calls if tc.get("id")]
        
        # Store thinking content if any was collected and thinking display is enabled
        if self.show_thinking and collected_thinking:
            self._log(f"\n{colors.MAGENTA}[THINKING SUMMARY]{colors.END}")
            self._log(f"{colors.MAGENTA}{collected_thinking}{colors.END}")
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
                        self._log_error(f"{colors.RED}[ERROR]{colors.END} Tool call arguments could not be parsed as JSON: {parse_error}")

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
        self._log(f"{colors.BLUE}[LLM INTERACTOR STARTED]{colors.END}")
        self._log(f"{colors.BLUE}API Base: {self.base_url}{colors.END}")
        self._log(f"{colors.BLUE}Model: {self.model}{colors.END}")
        self._log(f"{colors.BLUE}Auto-approve: {'Yes' if self.auto_approve else 'No'}{colors.END}")
        self._log(f"{colors.BLUE}Memory System: {'Enabled' if self.memory_enabled else 'Disabled'}{colors.END}")
        self._log(f"{colors.BLUE}Max prompt len: {self.max_prompt_len}{colors.END}")
        self._log(f"{colors.YELLOW}[USER REQUEST]{colors.END} {user_request}")
        self._log(f"{colors.CYAN}{'='*60}{colors.END}")
        
        # Initialize conversation with system prompt and user request
        self.conversation_history = [
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": user_request}
        ]
        
        iteration = 0
        
        try:
            while iteration < self.max_iterations:

                if self.debug:
                    self._dump_conversation_history()
            
                iteration += 1
                self._log(f"\n{colors.CYAN}[ITERATION {iteration}/{self.max_iterations}]{colors.END}")
                
                # Truncate conversation history if it exceeds max_prompt_len
                self._truncate_conversation_history()
                
                response = self.call_llm_api(list(self.conversation_history))
                
                # Check if this is a safety-stop response (empty validated messages)
                if not response.get("choices") or not response.get("choices", [{}])[0].get("message"):
                    self._log(f"\n{colors.YELLOW}[SAFETY STOP]{colors.END} API call returned no valid response. Ending interaction.")
                    break
                
                assistant_message = response["choices"][0]["message"]
                
                # Check if this is a terminal safety response from _validate_messages
                _content_raw = assistant_message.get("content") or ""
                if (_content_raw.strip().endswith(self.COMPLETION_MARKER) and
                    not assistant_message.get("tool_calls") and
                    not assistant_message.get("reasoning_content") and
                    len(_content_raw) < 200):
                    self._log(f"\n{colors.GREEN}[SAFETY STOP - TERMINAL]{colors.END} Terminal state reached. Ending interaction safely.")
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
                

                
                self._log(f"\n{colors.WHITE}[LLM RESPONSE]{colors.END}")
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
                    self._log(f"{colors.YELLOW}[INFO]{colors.END} {len(malformed_tool_calls)} tool call(s) had malformed JSON arguments. Requesting correction from LLM.")
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
                    self._log(f"{colors.YELLOW}[INFO]{colors.END} Correction messages appended. Continuing to next iteration for LLM to fix the tool calls.")
                    # Do not proceed with normal tool execution this iteration; let the loop continue
                    # so the LLM can re-issue corrected tool calls.
                    continue

                # Execute ALL tool calls if any were provided
                if tool_calls_info:
                    self._log(f"{colors.YELLOW}[INFO]{colors.END} Executing {len(tool_calls_info)} tool call(s)...")
                    
                    for idx, tc_info in enumerate(tool_calls_info):
                        tool_call_id = tc_info["tool_call_id"]
                        command = tc_info.get("command")
                        function_name = tc_info.get("function_name")
                        
                        if not command:
                            # Non-execute_bash tool call (memory functions); route to handle_function_call
                            self._log(f"{colors.YELLOW}[INFO]{colors.END} Tool call {idx+1}/{len(tool_calls_info)} has no command to execute (function={function_name}). Handling memory function call.")
                            if tool_call_id and function_name:
                                result = self.handle_function_call({"name": function_name, "arguments": tc_info["function_arguments"]})
                                self.conversation_history.append({
                                    "role": "tool",
                                    "tool_call_id": tool_call_id,
                                    "content": result
                                })
                            continue
                        
                        self._log(f"{colors.CYAN}[TOOL CALL {idx+1}/{len(tool_calls_info)}]{colors.END} {command}")
                        
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
                                self._log_error(f"{colors.RED}[TIMEOUT]{colors.END} {error_msg}")
                                
                                if tool_call_id:
                                    self.conversation_history.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call_id,
                                        "content": error_msg
                                    })
                            except Exception as e:
                                error_msg = f"Command execution failed: {str(e)}"
                                self._log_error(f"{colors.RED}[ERROR]{colors.END} {error_msg}")
                                
                                if tool_call_id:
                                    self.conversation_history.append({
                                        "role": "tool",
                                        "tool_call_id": tool_call_id,
                                        "content": error_msg
                                    })
                        else:
                            self._log(f"{colors.YELLOW}[INFO]{colors.END} Command not approved by user.")
                            
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
                    self._log(f"{colors.YELLOW}[INFO]{colors.END} No tool calls to execute in this iteration")
                    _content_check = content if isinstance(content, str) else ""
                    
                    if _content_check.strip().endswith(self.COMPLETION_MARKER) or self.COMPLETION_MARKER in _content_check:
                        # The assistant has signaled task completion
                        break
                    
                    # The assistant stopped without calling tools and without signaling
                    # completion.  This is a premature stop - the task is NOT finished.
                    # Inject a continuation message so the LLM keeps working until done.
                    self._log(f"{colors.YELLOW}[CONTINUATION]{colors.END} Assistant provided a response without tool calls and without completion signal. Task is not finished. Injecting continuation prompt.")
                    
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
                    self._log(f"\n{colors.GREEN}[{self.COMPLETION_MARKER} DETECTED - TASK COMPLETED SUCCESSFULLY]{colors.END}")
                    break
                
                # Check if we've reached max iterations
                if iteration >= self.max_iterations:
                    self._log(f"{colors.RED}[LIMIT REACHED]{colors.END} Maximum iterations ({self.max_iterations}) exceeded")
        
        finally:
            pass
        
        self._log(f"\n{colors.CYAN}{'='*60}{colors.END}")
        self._log(f"{colors.BLUE}[INTERACTOR FINISHED]{colors.END}")

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
    parser.add_argument("request", nargs="*", help="Task request")

    args = parser.parse_args()

    if not args.request:
        print(f"{colors.RED}[ERROR]{colors.END} Please provide a task request", file=sys.stderr)
        sys.exit(1)

    # Create and run interactor
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
        debug=args.debug
    )
    
    try:
        user_request = " ".join(args.request)
        interactor.run_interactor(user_request)
    except KeyboardInterrupt:
        interactor._log(f"\n{colors.YELLOW}[INTERRUPTED]{colors.END} Interactor stopped by user")
        sys.exit(0)
    except Exception as e:
        interactor._log_error(f"\n{colors.RED}[FATAL ERROR]{colors.END} An unexpected error occurred:")
        import traceback
        tb_str = traceback.format_exc()
        interactor._log_error(tb_str)
        sys.exit(1)

if __name__ == "__main__":
    main()
