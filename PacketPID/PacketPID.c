//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#include <sys/systm.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/if_media.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/kpi_interface.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <sys/errno.h>
#include "KernelResolver.h"
#include "RegKernCtl.h"
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

errno_t (*ifnet_flowid)(struct ifnet *ifp, uint32_t *flowid);

static char *sym_names[] = {
    "_tcbinfo",
    "_udbinfo",
    "_ifunit",
    "_in_pcblookup_hash",
    "_inp_get_soprocinfo",
    "_inp_findinpcb_procinfo",
    "_ifnet_flowid",
    NULL,
};

const size_t sym_num = sizeof(sym_names) / sizeof(char *) - 1;

static void **sym_addrs[sym_num] = {
    (void **)&tcbinfo_p,
    (void **)&udbinfo_p,
    (void **)&ifunit,
    (void **)&in_pcblookup_hash,
    (void **)&inp_get_soprocinfo,
    (void **)&inp_findinpcb_procinfo,
    (void **)&ifnet_flowid,
};


static int InitFunctions() {
    // find kernel base address
    if(find_kernel_baseaddr() != 0)
    {
        DLOG( "[+] Can't find KERNEL_MH_START_ADDR!\n" );
        return -1;
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
        return -1;
    }
    
    return 0;
}

static ifnet_t ifaces[IFACE_BUFFER_SIZE] = {NULL,};

static uint32_t iface_flowhash[IFACE_BUFFER_SIZE] = {0,};

static int LoadInterfaces() {
    ifnet_t *interfaces;
    ifaddr_t *addrs;
    uint32_t count = 0;
    int p = 0;
    
    // get list of ifnet structure
    if (ifnet_list_get(IFNET_FAMILY_ANY, &interfaces, &count) != 0) {
        return -1;
    }
    for (int i = 0; i < count; i++) {
        int found = 0;
        if (ifnet_get_address_list(interfaces[i], &addrs) != 0) {
            return -1;
        }
        for (int k = 0; addrs[k]; k++)
            if (ifaddr_address_family(addrs[k]) == AF_INET)
                found = 1;
        ifnet_free_address_list(addrs);
        if (found && p < IFACE_BUFFER_SIZE - 1) {
            ifaces[p++] = interfaces[i];
        }
    }
    // free the ifnet list
    // seems that reference count is not needed
    ifnet_list_free(interfaces);
    interfaces = NULL;
    ifaces[p] = NULL;
    
    // finally extract flowhash of each interface
    for (int i = 0; ifaces[i]; i++) {
        ifnet_flowid((struct ifnet *)ifaces[i], &iface_flowhash[i]);
        DLOG("Listen on iface %s%d: type %d, flowID %u @ %p\n",
             ifnet_name(ifaces[i]),
             ifnet_unit(ifaces[i]),
             ifnet_type(ifaces[i]),
             iface_flowhash[i], ifaces[i]);
    }

    DLOG("[+] Network interfaces count: %u\n", count);
    return 0;
}



kern_return_t PacketPID_start(kmod_info_t * ki, void *d)
{
    // Load kernel functions
    if(InitFunctions() != 0)
    {
        DLOG( "[+] Kernel functions load error.\n" );
        return KERN_FAILURE;
    }
    
    // Find pointers of network interfaces
    if (LoadInterfaces() != 0) {
        DLOG( "[+] Network interfaces load error.\n" );
        return KERN_FAILURE;
    }
    
    // register kernel control structure
    if (RegKernelControl() != 0) {
        DLOG( "[+] Kernel control register error.\n" );
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

kern_return_t PacketPID_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
