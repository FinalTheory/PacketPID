//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015年 Baidu Inc. All rights reserved.
//

#include <sys/systm.h>
#include "KernelResolver.h"

static char *sym_names[] = {
    "_tcbinfo",
    "_udbinfo",
    "_in_pcblookup_hash",
    "_inp_get_soprocinfo",
    "_inp_findinpcb_procinfo",
    NULL
};

const size_t sym_num = sizeof(sym_names) / sizeof(char *) - 1;

static void *sym_addrs[sym_num] = {NULL,};


kern_return_t PacketPID_start(kmod_info_t * ki, void *d)
{
    // find kernel base address
    if( find_kernel_baseaddr() != 0 )
    {
        DLOG( "[+] Can't find KERNEL_MH_START_ADDR!\n" );
        return KERN_FAILURE;
    }
    
    // found all needed symbols
    int num_found = find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR, sym_names, sym_addrs);
    for (int i = 0; sym_names[i]; i++) {
        DLOG("[+] Symbol %s @ %p\n", sym_names[i], sym_addrs[i]);
    }
    
    // check if all symbols are found
    DLOG("[+] Symbols found: %d\n", num_found);
    if (num_found != sym_num) {
        DLOG("There are unknown symbols, exit.\n");
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

kern_return_t PacketPID_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
