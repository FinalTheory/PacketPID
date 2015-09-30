/*
 * Original KernelResolver.c
 * by snare (snare@ho.ax)
 *
 * Mountain Lion port
 * by @_rc0r
 *
 * Used by PacketPID kernel extension
 * Created by huangyan13@baidu.com on 15/9/30.
 * Copyright © 2015年 Baidu Inc. All rights reserved.
 *
 * This is a simple example of how to resolve symbols in the kernel from within
 * a kernel extension. Symbols can be solved by using the kernel image from disk
 * (find_symbol_from_disk)[removed by huangyan13@baidu.com] and from memory (find_symbol).
 *
 * See the following URLs for more info:
 * 1. http://ho.ax/posts/2012/02/resolving-kernel-symbols/
 * 2. https://reverse.put.as/2012/02/14/a-small-improvement-to-os-x-rootkitery-bruteforcing-sysent-discovery-fast-easy/
 * 3. http://reverse.put.as/2013/05/08/there-is-an-error-in-my-syscan-slides/
 *
 */

#include "KernelResolver.h"
#include <sys/fcntl.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/vnode.h>

uint64_t KERNEL_MH_START_ADDR;


struct segment_command_64 *
find_segment_64(struct mach_header_64 *mh, const char *segname)
{
    struct load_command *lc;
    struct segment_command_64 *seg, *foundseg = NULL;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT_64) {
            /* Check load command's segment name */
            seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, segname) == 0) {
                foundseg = seg;
                break;
            }
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the segment (NULL if we didn't find it) */
    return foundseg;
}

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc;
    
    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }
        
        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }
    
    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

// static struct segment_command_64 *mlc = NULL;
static struct symtab_command *msymtab = NULL;
static struct segment_command_64 *mlinkedit = NULL;

int
find_symbol(struct mach_header_64 *mh, char *names[], void *sym_addrs[])
{
    char *str;
    uint64_t i;
    void *mstrtab = NULL;
    struct nlist_64 *nl = NULL;
    
    /*
     * Check header
     */
    if (mh->magic != MH_MAGIC_64) {
        DLOG("FAIL: magic number doesn't match - 0x%x\n", mh->magic);
        return 0;
    }
    
    /*
     * Find TEXT section
     * this is not needed, comment out (huangyan13@baidu.com)
     */
//    if (mlc == NULL) {
//        mlc = find_segment_64(mh, SEG_TEXT);
//        if (!mlc) {
//            DLOG("FAIL: couldn't find __TEXT\n");
//            return NULL;
//        }
//    }
    
    /*
     * Find the LINKEDIT and SYMTAB sections
     */
    if (mlinkedit == NULL) {
        mlinkedit = find_segment_64(mh, SEG_LINKEDIT);
        if (!mlinkedit) {
            DLOG("FAIL: couldn't find __LINKEDIT\n");
            return 0;
        }
    }
    
    if (msymtab == NULL) {
        msymtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
        if (!msymtab) {
            DLOG("FAIL: couldn't find SYMTAB\n");
            return 0;
        }
    }
    
    /*
     * Enumerate symbols until we find the one we're after
     *
     *  Be sure to use NEW calculation STRTAB in Mountain Lion!
     */
    mstrtab = (void *)((int64_t)mlinkedit->vmaddr + (msymtab->stroff - mlinkedit->fileoff));
    
    int num_found = 0;
    
    // First nlist_64 struct is NOW located @:
    for (i = 0, nl = (struct nlist_64 *)(mlinkedit->vmaddr + (msymtab->symoff - mlinkedit->fileoff));
         i < msymtab->nsyms;
         i++, nl = (struct nlist_64 *)((uint64_t)nl + sizeof(struct nlist_64)))
    {
        str = (char *)mstrtab + nl->n_un.n_strx;
        for (int k = 0; names[k]; k++) {
            if (strcmp(str, names[k]) == 0) if (NULL == sym_addrs[k]) {
                num_found++;
                sym_addrs[k] = (void *)nl->n_value;
            }
        }
    }
    
    /* Return the address (0 if we didn't find it) */
    return num_found;
}

uint64_t find_kernel_baseaddr()
{
    uint8_t idtr[ 10 ];
    uint64_t idt = 0;
    
    __asm__ volatile ( "sidt %0": "=m" ( idtr ) );
    
    idt = *( ( uint64_t * ) &idtr[ 2 ] );
    struct descriptor_idt *int80_descriptor = NULL;
    uint64_t int80_address = 0;
    uint64_t high = 0;
    uint32_t middle = 0;
    
    int80_descriptor = _MALLOC( sizeof( struct descriptor_idt ), M_TEMP, M_WAITOK );
    bcopy( (void*)idt, int80_descriptor, sizeof( struct descriptor_idt ) );
    
    high = ( unsigned long ) int80_descriptor->offset_high << 32;
    middle = ( unsigned int ) int80_descriptor->offset_middle << 16;
    int80_address = ( uint64_t )( high + middle + int80_descriptor->offset_low );
    
    uint64_t temp_address = int80_address;
    uint8_t *temp_buffer = _MALLOC( 4, M_TEMP, M_WAITOK );
    
    while( temp_address > 0 )
    {
        bcopy( ( void * ) temp_address, temp_buffer, 4 );
        if ( *( uint32_t * )( temp_buffer ) == MH_MAGIC_64 )
        {
            KERNEL_MH_START_ADDR = temp_address;
            return 0;
        }
        temp_address -= 1;
    }
    
    return -1;
}
