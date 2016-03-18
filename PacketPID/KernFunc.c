//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#define XNU_KERNEL_PRIVATE 1
#define BSD_KERNEL_PRIVATE 1
#define SO_PROCINFO 1
#define PRIVATE 1
#define KERNEL 1
#define APPLE 1

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in_pcb.h>
#include "KernFunc.h"
#include "PacketPID.h"
#include "KernelResolver.h"

struct inpcbinfo *tcbinfo_p;

struct inpcbinfo *udbinfo_p;

struct inpcbinfo *ripcbinfo_p;

struct ifnet *(*ifunit_p)(const char *name);

struct inpcb *(*in_pcblookup_hash_p)(struct inpcbinfo *pcbinfo,
                                     struct in_addr faddr, u_int fport_arg,
                                     struct in_addr laddr, u_int lport_arg,
                                     int wildcard, struct ifnet *ifp);

void (*inp_get_soprocinfo_p)(struct inpcb *inp, struct so_procinfo *soprocinfo);

int (*inp_findinpcb_procinfo_p)(struct inpcbinfo *pcbinfo, uint32_t flowhash,
                                struct so_procinfo *soprocinfo);

errno_t (*ifnet_flowid_p)(struct ifnet *ifp, uint32_t *flowid);

void (*lck_rw_lock_shared_p)(lck_rw_t *lck);

lck_rw_type_t (*lck_rw_done_p)(lck_rw_t *lck);

int (*in_pcb_checkstate_p)(struct inpcb *pcb, int mode, int locked);

boolean_t (*inp_restricted_recv_p)(struct inpcb *inp, struct ifnet *ifp);

static char *sym_names[] = {
        "_tcbinfo",
        "_udbinfo",
        "_ripcbinfo",
        "_ifunit",
        "_in_pcblookup_hash",
        "_inp_get_soprocinfo",
        "_inp_findinpcb_procinfo",
        "_ifnet_flowid",
        "_lck_rw_lock_shared",
        "_lck_rw_done",
        "_in_pcb_checkstate",
        "_inp_restricted_recv",
        NULL,
};

static const size_t sym_num = sizeof(sym_names) / sizeof(char *) - 1;

static void **sym_addrs[sym_num] = {
        (void **)&tcbinfo_p,
        (void **)&udbinfo_p,
        (void **)&ripcbinfo_p,
        (void **)&ifunit_p,
        (void **)&in_pcblookup_hash_p,
        (void **)&inp_get_soprocinfo_p,
        (void **)&inp_findinpcb_procinfo_p,
        (void **)&ifnet_flowid_p,
        (void **)&lck_rw_lock_shared_p,
        (void **)&lck_rw_done_p,
        (void **)&in_pcb_checkstate_p,
        (void **)&inp_restricted_recv_p,
};

int InitFunctions() {
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

int LoadInterfaces() {
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
        for (int k = 0; addrs[k]; k++) {
            if (ifaddr_address_family(addrs[k]) == AF_INET) {
                found = 1;
            }
        }
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
        ifnet_flowid_p((struct ifnet *)ifaces[i], &iface_flowhash[i]);
        DLOG("[INFO] Listen on iface %s%d: type %d, flowID %u @ %p\n",
             ifnet_name(ifaces[i]),
             ifnet_unit(ifaces[i]),
             ifnet_type(ifaces[i]),
             iface_flowhash[i], ifaces[i]);
    }

    DLOG("[INFO] Network interfaces count: %u\n", count);
    return 0;
}

/*
 * Lookup PCB in hash list.
 */
struct inpcb *
in_pcblookup_hash(struct inpcbinfo *pcbinfo, struct in_addr faddr,
                  u_int fport_arg, struct in_addr laddr, u_int lport_arg, int wildcard,
                  struct ifnet *ifp)
{
    struct inpcbhead *head;
    struct inpcb *inp;
    u_short fport = fport_arg, lport = lport_arg;
    struct inpcb *local_wild = NULL;
#if INET6
    struct inpcb *local_wild_mapped = NULL;
#endif /* INET6 */
    
    /*
     * We may have found the pcb in the last lookup - check this first.
     */
    
    lck_rw_lock_shared(pcbinfo->ipi_lock);
    
    /*
     * First look for an exact match.
     */
    head = &pcbinfo->ipi_hashbase[INP_PCBHASH(faddr.s_addr, lport, fport,
                                              pcbinfo->ipi_hashmask)];
    LIST_FOREACH(inp, head, inp_hash) {
#if INET6
        if (!(inp->inp_vflag & INP_IPV4))
            continue;
#endif /* INET6 */
        if (inp_restricted_recv_p(inp, ifp))
            continue;
        
        if (inp->inp_faddr.s_addr == faddr.s_addr &&
            inp->inp_laddr.s_addr == laddr.s_addr &&
            inp->inp_fport == fport &&
            inp->inp_lport == lport) {
            /*
             * Found.
             */
            if (in_pcb_checkstate_p(inp, WNT_ACQUIRE, 0) !=
                WNT_STOPUSING) {
                lck_rw_done_p(pcbinfo->ipi_lock);
                return (inp);
            } else {
                /* it's there but dead, say it isn't found */
                lck_rw_done_p(pcbinfo->ipi_lock);
                return (NULL);
            }
        }
    }
    
    if (!wildcard) {
        /*
         * Not found.
         */
        lck_rw_done_p(pcbinfo->ipi_lock);
        return (NULL);
    }
    
    head = &pcbinfo->ipi_hashbase[INP_PCBHASH(INADDR_ANY, lport, 0,
                                              pcbinfo->ipi_hashmask)];
    LIST_FOREACH(inp, head, inp_hash) {
#if INET6
        if (!(inp->inp_vflag & INP_IPV4))
            continue;
#endif /* INET6 */
        if (inp_restricted_recv_p(inp, ifp))
            continue;
        
        if (inp->inp_faddr.s_addr == INADDR_ANY &&
            inp->inp_lport == lport) {
            if (inp->inp_laddr.s_addr == laddr.s_addr) {
                if (in_pcb_checkstate_p(inp, WNT_ACQUIRE, 0) !=
                    WNT_STOPUSING) {
                    lck_rw_done_p(pcbinfo->ipi_lock);
                    return (inp);
                } else {
                    /* it's dead; say it isn't found */
                    lck_rw_done_p(pcbinfo->ipi_lock);
                    return (NULL);
                }
            } else if (inp->inp_laddr.s_addr == INADDR_ANY) {
#if INET6
                if (SOCK_CHECK_DOM(inp->inp_socket, PF_INET6))
                    local_wild_mapped = inp;
                else
#endif /* INET6 */
                    local_wild = inp;
            }
        }
    }
    if (local_wild == NULL) {
#if INET6
        if (local_wild_mapped != NULL) {
            if (in_pcb_checkstate_p(local_wild_mapped,
                                  WNT_ACQUIRE, 0) != WNT_STOPUSING) {
                lck_rw_done_p(pcbinfo->ipi_lock);
                return (local_wild_mapped);
            } else {
                /* it's dead; say it isn't found */
                lck_rw_done_p(pcbinfo->ipi_lock);
                return (NULL);
            }
        }
#endif /* INET6 */
        lck_rw_done_p(pcbinfo->ipi_lock);
        return (NULL);
    }
    if (in_pcb_checkstate_p(local_wild, WNT_ACQUIRE, 0) != WNT_STOPUSING) {
        lck_rw_done_p(pcbinfo->ipi_lock);
        return (local_wild);
    }
    /*
     * It's either not found or is already dead.
     */
    lck_rw_done_p(pcbinfo->ipi_lock);
    return (NULL);
}

int
inp_findinpcb_procinfo_by_tuple(struct inpcbinfo *pcbinfo,
                                struct in_addr faddr, u_int fport_arg,
                                struct in_addr laddr, u_int lport_arg,
                                struct so_procinfo *soprocinfo) {
    u_short fport = fport_arg, lport = lport_arg;
    struct inpcb *inp = NULL;
    int found = 0;
    
    bzero(soprocinfo, sizeof(struct so_procinfo));
    
    lck_rw_lock_shared_p(pcbinfo->ipi_lock);
    LIST_FOREACH(inp, pcbinfo->ipi_listhead, inp_list) {
        if (inp->inp_state != INPCB_STATE_DEAD &&
            inp->inp_socket != NULL &&
            inp->inp_faddr.s_addr == faddr.s_addr &&
            inp->inp_laddr.s_addr == laddr.s_addr &&
            inp->inp_fport == fport &&
            inp->inp_lport == lport) {
            found = 1;
            inp_get_soprocinfo_p(inp, soprocinfo);
            break;
        }
    }
    lck_rw_done_p(pcbinfo->ipi_lock);
    
    return (found);
}

errno_t
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

    faddr.s_addr = data_ptr->sock_info.saddr;
    laddr.s_addr = data_ptr->sock_info.daddr;
    fport = data_ptr->sock_info.source;
    lport = data_ptr->sock_info.dest;
    
    // set pcbinfo pointer and match type by protocol type
    if (data_ptr->proto == IPPROTO_TCP) {
        pcbinfo = tcbinfo_p;
    } else if (data_ptr->proto == IPPROTO_UDP) {
        pcbinfo = udbinfo_p;
        wildcard = 1;
    } else {
        pcbinfo = ripcbinfo_p;
    }

    if (pcbinfo != NULL) {
        if (opt & KERN_CTL_OUTBOUND) {
            // search outbound list
            found = inp_findinpcb_procinfo_by_tuple(pcbinfo, laddr, lport,
                                                    faddr, fport, &data_ptr->proc);
        } else if (opt & KERN_CTL_INBOUND) {
            // search inbound hash table
            ifp = ifunit_p(data_ptr->iface);
            if (ifp != NULL) {
                // if we can find the inbound interface
                // then just search the hash table
                inp = in_pcblookup_hash_p(pcbinfo, faddr, fport,
                                          laddr, lport, wildcard, ifp);
            } else {
                // search all avaliable interfaces
                for (int i = 0; ifaces[i]; i++) {
                    ifp = (struct ifnet *)ifaces[i];
                    inp = in_pcblookup_hash_p(pcbinfo, faddr, fport,
                                              laddr, lport, wildcard, ifp);
                    if (inp != NULL) { break; }
                }
            }
            // if we found correct in_pcb block
            // just extract all data
            if (inp != NULL) {
                if (inp->inp_state != INPCB_STATE_DEAD &&
                    inp->inp_socket != NULL) {
                    found = 1;
                    inp_get_soprocinfo_p(inp, &data_ptr->proc);
                }
                /*
                    in function in_pcblookup_hash(),
                    they increased a reference count of this in_pcb block,
                    if you didn't release it, this is just like a memory leak,
                    and when there is no enough memory in buffer,
                    the entire TCP connection is reseted by RST packet.
                 */
                in_pcb_checkstate_p(inp, WNT_RELEASE, 0);
            }
        }
    } else {
        DLOG("[WARNING] Unsupported protocol.\n");
    }
    if (found) {
        data_ptr->pid = data_ptr->proc.spi_pid;
        data_ptr->epid = data_ptr->proc.spi_epid;
    } else {
        // if process info is not found, set result to -1
        data_ptr->pid = -1;
        data_ptr->epid = -1;
    }

    return 0;
}
