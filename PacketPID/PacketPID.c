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
#include <sys/kern_control.h>

#include "KernelResolver.h"
#include "RegKernCtl.h"
#include "PacketPID.h"

struct inpcbinfo *tcbinfo_p;

struct inpcbinfo *udbinfo_p;

struct inpcbinfo *ripcbinfo_p;

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
    "_ripcbinfo",
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
    (void **)&ripcbinfo_p,
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
        DLOG( "[FATAL] Can't find KERNEL_MH_START_ADDR!\n" );
        return -1;
    }
    // found all needed symbols
    int num_found = find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR, sym_names, sym_addrs);
    for (int i = 0; sym_names[i]; i++) {
        DLOG("[INFO] Symbol %s @ %p\n", sym_names[i], *(sym_addrs[i]));
    }
    
    // check if all symbols are found
    DLOG("[INFO] Symbols found: %d\n", num_found);
    if (num_found != sym_num) {
        DLOG("[ERROR] There are unknown symbols, exit.\n");
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
        DLOG("[INFO] Listen on iface %s%d: type %d, flowID %u @ %p\n",
             ifnet_name(ifaces[i]),
             ifnet_unit(ifaces[i]),
             ifnet_type(ifaces[i]),
             iface_flowhash[i], ifaces[i]);
    }

    DLOG("[INFO] Network interfaces count: %u\n", count);
    return 0;
}

static errno_t
kern_ctl_getopt_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
                     int opt, void *data, size_t *len) {
    qry_data_t data_ptr = (qry_data_t)data;
    
    int found = 0;
    struct ifnet *ifp = NULL;
    struct inpcb *inp = NULL;
    struct inpcbinfo *pcbinfo = NULL;
    struct in_addr faddr, laddr;
    u_short fport, lport;
    int wildcard = 0;
    
    faddr.s_addr = data_ptr->saddr;
    laddr.s_addr = data_ptr->daddr;
    fport = data_ptr->source;
    lport = data_ptr->dest;
    
    if (data_ptr->proto == IPPROTO_TCP) {
        pcbinfo = tcbinfo_p;
    } else if (data_ptr->proto == IPPROTO_UDP) {
        pcbinfo = udbinfo_p;
        wildcard = 1;
    }
    
    if (pcbinfo != NULL) {
        if (data_ptr->outgoing) {
            // search outbound list
//            if (data_ptr->proto == IPPROTO_TCP)
//                found = inp_findinpcb_procinfo(tcbinfo_p, hdr->pth_flowid,
//                                               &data_ptr->proc);
//            else if (data_ptr->proto == IPPROTO_UDP)
//                found = inp_findinpcb_procinfo(udbinfo_p, hdr->pth_flowid,
//                                               &data_ptr->proc);
//            else
//                found = inp_findinpcb_procinfo(ripcbinfo_p, hdr->pth_flowid,
//                                               &data_ptr->proc);
        } else {
            // search inbound hash table
            ifp = ifunit(data_ptr->iface);
            if (ifp != NULL) {
                // if we can find the inbound interface
                // then just search the hash table
                inp = in_pcblookup_hash(pcbinfo, faddr, fport,
                                        laddr, lport, wildcard, ifp);
            } else {
                // search all avaliable interfaces
                for (int i = 0; ifaces[i]; i++) {
                    ifp = (struct ifnet *)ifaces[i];
                    inp = in_pcblookup_hash(pcbinfo, faddr, fport,
                                            laddr, lport, wildcard, ifp);
                    if (inp != NULL) break;
                }
            }
            // if we found correct in_pcb block
            // just extract all data
            if (inp != NULL) {
                found = 1;
                // seems all right without guard here
                // but may leads to a kernel crash
                // if (inp->inp_state != INPCB_STATE_DEAD &&
                //     inp->inp_socket != NULL) {
                // }
                inp_get_soprocinfo(inp, &data_ptr->proc);
            }
        }
    } else {
        DLOG("[WARNING] Unsupported protocol.\n");
    }
    if (!found) {
        // if process info is not found, clear the result
        memset(&data_ptr->proc, 0, sizeof(data_ptr->proc));
    }
    
    return 0;
}

kern_return_t PacketPID_start(kmod_info_t * ki, void *d)
{
    int ret_val;
    // Load kernel functions
    if(InitFunctions() != 0)
    {
        DLOG("[FATAL] Kernel functions load error.\n");
        return KERN_FAILURE;
    }
    
    // Find pointers of network interfaces
    if (LoadInterfaces() != 0) {
        DLOG("[FATAL] Network interfaces load error.\n");
        return KERN_FAILURE;
    }
    
    // register kernel control structure
    if ((ret_val = RegKernelControl(kern_ctl_getopt_func)) != 0) {
        DLOG("[FATAL] Kernel control register error: %d.\n", ret_val);
        return KERN_FAILURE;
    }
    
    return KERN_SUCCESS;
}

kern_return_t PacketPID_stop(kmod_info_t *ki, void *d)
{
    // unregister the kernel control function
    if (CleanKernelControl() != 0) {
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}
