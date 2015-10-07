//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//
#include <sys/systm.h>
#define KEXT_PRIVATE
#include "PacketPID.h"
#include "RegKernCtl.h"
#include "KernFunc.h"


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
