//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#ifndef RegKernCtl_h
#define RegKernCtl_h

/*
 * Socket process information
 */
struct so_procinfo {
    pid_t		spi_pid;
    pid_t		spi_epid;
    uuid_t		spi_uuid;
    uuid_t		spi_euuid;
};

struct qry_data
{
    // store query result
    struct so_procinfo proc;
    // store query info
    char iface[8];
    u_short source;
    u_short dest;
    u_int32_t saddr;
    u_int32_t daddr;
    u_char outgoing;
    u_char proto;
};

typedef struct qry_data *qry_data_t;

errno_t RegKernelControl(ctl_getopt_func kern_ctl_getopt_func);

errno_t CleanKernelControl();

#endif /* RegKernCtl_h */
