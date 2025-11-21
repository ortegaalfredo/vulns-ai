/*
 * Simple test program that uses the upipe library to process an H.265 file.
 * This will naturally trigger upipe_h265f_stream_parse_short_term_ref_pic_set()
 * when the SPS contains short-term reference picture sets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>

/* Include upipe headers */
#include "../../include/upipe/ubase.h"
#include "../../include/upipe/upipe.h"
#include "../../include/upipe/uref.h"
#include "../../include/upipe/uref_std.h"
#include "../../include/upipe/uprobe.h"
#include "../../include/upipe/uprobe_prefix.h"
#include "../../include/upipe/uref_block.h"
#include "../../include/upipe/ubuf.h"
#include "../../include/upipe/ubuf_block_mem.h"
#include "../../include/upipe/uref_block_flow.h"
#include "../../include/upipe/udict.h"
#include "../../include/upipe/udict_inline.h"
#include "../../include/upipe/umem.h"
#include "../../include/upipe/umem_pool.h"
#include "../../include/upipe-framers/upipe_h265_framer.h"

/* Simple probe to capture events */
static int catch(struct uprobe *uprobe, struct upipe *upipe,
                 int event, va_list args)
{
    switch (event) {
        default:
            break;
    }
    return UBASE_ERR_NONE;
}

/* Simple output pipe that just discards data */
static void output_helper(struct upipe *upipe, struct uref *uref, void *unused)
{
    printf("Received processed frame\n");
    uref_free(uref);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: %s <h265_file>\n", argv[0]);
        return 1;
    }

    printf("Processing H.265 file: %s\n", argv[1]);
    
    /* Initialize upipe components */
    struct uprobe uprobe;
    uprobe_init(&uprobe, catch, NULL);
    
    /* Define pool sizes - must be <= UINT16_MAX */
    #define UREF_POOL_DEPTH 20
    #define UDICT_POOL_DEPTH 20
    #define UMEM_POOL_DEPTH 20
    
    /* Initialize umem manager first (needed by udict) */
    struct umem_mgr *umem_mgr = umem_pool_mgr_alloc_simple(UMEM_POOL_DEPTH);
    if (!umem_mgr) {
        printf("Failed to create umem manager\n");
        return 1;
    }
    
    /* Initialize udict manager */
    struct udict_mgr *udict_mgr = udict_inline_mgr_alloc(UDICT_POOL_DEPTH, umem_mgr, -1, -1);
    if (!udict_mgr) {
        printf("Failed to create udict manager\n");
        umem_mgr_release(umem_mgr);
        return 1;
    }
    
    /* Initialize uref manager */
    struct uref_mgr *uref_mgr = uref_std_mgr_alloc(UREF_POOL_DEPTH, udict_mgr, 0);
    if (!uref_mgr) {
        printf("Failed to create uref manager\n");
        udict_mgr_release(udict_mgr);
        umem_mgr_release(umem_mgr);
        return 1;
    }
    
    /* Initialize ubuf manager */
    struct ubuf_mgr *ubuf_mgr = ubuf_block_mem_mgr_alloc(UREF_POOL_DEPTH, UREF_POOL_DEPTH, umem_mgr, -1, 0, -1, 0);
    if (!ubuf_mgr) {
        printf("Failed to create ubuf manager\n");
        uref_mgr_release(uref_mgr);
        udict_mgr_release(udict_mgr);
        umem_mgr_release(umem_mgr);
        return 1;
    }
    
    /* Create H.265 framer */
    struct upipe_mgr *upipe_h265f_mgr = upipe_h265f_mgr_alloc();
    if (!upipe_h265f_mgr) {
        printf("Failed to create H.265 framer manager\n");
        ubuf_mgr_release(ubuf_mgr);
        uref_mgr_release(uref_mgr);
        return 1;
    }
    
    struct upipe *h265f = upipe_void_alloc(upipe_h265f_mgr,
                    uprobe_pfx_alloc(uprobe_use(&uprobe), UPROBE_LOG_DEBUG,
                                     "h265f"));
    if (!h265f) {
        printf("Failed to create H.265 framer\n");
        upipe_mgr_release(upipe_h265f_mgr);
        ubuf_mgr_release(ubuf_mgr);
        uref_mgr_release(uref_mgr);
        return 1;
    }
    
    /* Set up flow definition */
    struct uref *flow_def = uref_block_flow_alloc_def(uref_mgr, "h265.h265");
    if (!flow_def) {
        printf("Failed to create flow definition\n");
        upipe_release(h265f);
        upipe_mgr_release(upipe_h265f_mgr);
        ubuf_mgr_release(ubuf_mgr);
        uref_mgr_release(uref_mgr);
        return 1;
    }
    
    upipe_input(h265f, flow_def, NULL);
    
    /* Open the H.265 file */
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        printf("Failed to open file: %s\n", argv[1]);
        uref_free(flow_def);
        upipe_release(h265f);
        upipe_mgr_release(upipe_h265f_mgr);
        ubuf_mgr_release(ubuf_mgr);
        uref_mgr_release(uref_mgr);
        return 1;
    }
    
    /* Read file and feed to H.265 framer */
    uint8_t buffer[4096];
    ssize_t bytes_read;
    
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        struct uref *uref = uref_block_alloc(uref_mgr, ubuf_mgr, bytes_read);
        if (!uref) {
            printf("Failed to allocate uref\n");
            break;
        }
        
        uint8_t *buf;
        int size = -1;
        if (ubase_check(uref_block_write(uref, 0, &size, &buf))) {
            memcpy(buf, buffer, bytes_read);
            uref_block_unmap(uref, 0);
            
            /* Feed to H.265 framer - this will trigger the parsing */
            printf("Feeding %zd bytes to H.265 framer\n", bytes_read);
            upipe_input(h265f, uref, NULL);
        } else {
            uref_free(uref);
        }
    }
    
    close(fd);
    
    /* Clean up */
    upipe_release(h265f);
    upipe_mgr_release(upipe_h265f_mgr);
    ubuf_mgr_release(ubuf_mgr);
    umem_mgr_release(umem_mgr);
    uref_mgr_release(uref_mgr);
    udict_mgr_release(udict_mgr);
    
    printf("Processing complete\n");
    return 0;
}