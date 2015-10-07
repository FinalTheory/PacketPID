//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#ifndef RegKernCtl_h
#define RegKernCtl_h

#include <sys/kern_control.h>

errno_t RegKernelControl(ctl_getopt_func kern_ctl_getopt_func);

errno_t CleanKernelControl();

#endif /* RegKernCtl_h */
