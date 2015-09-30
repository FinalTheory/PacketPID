//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#include <sys/systm.h>
#include <net/if.h>
#include "net/if_var.h"
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include "KernelResolver.h"
#include "PacketPID.h"

struct inpcbinfo *tcbinfo_p;

struct inpcbinfo *udbinfo_p;

struct ifnet * (*ifunit)(const char *name);

struct inpcb * (*in_pcblookup_hash)(struct inpcbinfo *pcbinfo,
                                    struct in_addr faddr, u_int fport_arg,
                                    struct in_addr laddr, u_int lport_arg,
                                    int wildcard, struct ifnet *ifp);

void (*inp_get_soprocinfo)(struct inpcb *inp, struct so_procinfo *soprocinfo);

int (*inp_findinpcb_procinfo)(struct inpcbinfo *pcbinfo, uint32_t flowhash,
                              struct so_procinfo *soprocinfo);

static char *sym_names[] = {
    "_tcbinfo",
    "_udbinfo",
    "_ifunit",
    "_in_pcblookup_hash",
    "_inp_get_soprocinfo",
    "_inp_findinpcb_procinfo",
    NULL
};

const size_t sym_num = sizeof(sym_names) / sizeof(char *) - 1;

static void **sym_addrs[sym_num] = {
    (void **)&tcbinfo_p,
    (void **)&udbinfo_p,
    (void **)&ifunit,
    (void **)&in_pcblookup_hash,
    (void **)&inp_get_soprocinfo,
    (void **)&inp_findinpcb_procinfo,
};

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
        DLOG("[+] Symbol %s @ %p\n", sym_names[i], *(sym_addrs[i]));
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
