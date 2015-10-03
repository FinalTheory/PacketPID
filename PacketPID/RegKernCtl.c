//
//  RegKernCtl.c
//  PacketPID
//
//  Created by baidu on 15/10/3.
//  Copyright © 2015年 baidu. All rights reserved.
//

#include <sys/systm.h>
#include <sys/kern_control.h>
#include "RegKernCtl.h"

static const char ctl_name[] = "org.baidu.PacketPID";

errno_t kern_ctl_connect_func(kern_ctl_ref kctlref,
                              struct sockaddr_ctl *sac,
                              void **unitinfo) {
    // do nothing
    return 0;
}

errno_t kern_ctl_disconnect_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo) {
    // do nothing
    return 0;
}

errno_t kern_ctl_send_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
                           mbuf_t m, int flags) {
    return 0;
}


errno_t kern_ctl_setopt_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
                             int opt, void *data, size_t len) {
    return 0;
}

errno_t kern_ctl_getopt_func(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo,
                             int opt, void *data, size_t *len) {
    return 0;
}

int RegKernelControl() {
    errno_t error;
    // Initialize control
    struct kern_ctl_reg ep_ctl;
    kern_ctl_ref kctlref;
    bzero(&ep_ctl, sizeof(ep_ctl));
    // this ID would be dynamically assigned
    ep_ctl.ctl_id = 0;
    // leave unit number to be zero
    ep_ctl.ctl_unit = 0;
    strncpy(ep_ctl.ctl_name, ctl_name, strlen(ctl_name) + 1);
    // use kernel control sockets of type SOCK_DGRAM
    // so leave this flag to be zero
    ep_ctl.ctl_flags = 0;
    
    ep_ctl.ctl_send = kern_ctl_send_func;
    ep_ctl.ctl_getopt = kern_ctl_getopt_func;
    ep_ctl.ctl_setopt = kern_ctl_setopt_func;
    ep_ctl.ctl_connect = kern_ctl_connect_func;
    ep_ctl.ctl_disconnect = kern_ctl_disconnect_func;
    
    // register kernel control
    error = ctl_register(&ep_ctl, &kctlref);
    if (error != 0) {
        return -1;
    }
    return 0;
}
