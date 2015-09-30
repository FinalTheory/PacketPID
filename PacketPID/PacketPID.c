//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015年 Baidu Inc. All rights reserved.
//

#include <mach/mach_types.h>
#include <sys/systm.h>
#include "KernelResolver.h"

kern_return_t PacketPID_start(kmod_info_t * ki, void *d)
{
    if( find_kernel_baseaddr() != 0 )
    {
        DLOG( "[+] Can't find KERNEL_MH_START_ADDR!\n" );
        return KERN_FAILURE;
    }
    
    void *mkmod;
    
    DLOG("[+] _allproc @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_allproc"));
    DLOG("[+] _proc_lock @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_proc_lock"));
    DLOG("[+] _kauth_cred_setuidgid @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_kauth_cred_setuidgid"));
    DLOG("[+] __ZN6OSKext13loadFromMkextEjPcjPS0_Pj @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "__ZN6OSKext13loadFromMkextEjPcjPS0_Pj"));
    DLOG("[+] _nsysent @ %p\n",
         find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR,
                     "_nsysent"));
    mkmod = find_symbol((struct mach_header_64 *)KERNEL_MH_START_ADDR, "_kmod");
    DLOG("[+] _kmod from mem. @ %p\n", mkmod );
    return KERN_SUCCESS;
}

kern_return_t PacketPID_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
