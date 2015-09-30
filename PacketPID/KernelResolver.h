//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#ifndef KernelResolver_h
#define KernelResolver_h

#include <mach/mach_types.h>
#include <mach-o/loader.h>

#ifdef DEBUG
#define DLOG(args...)   printf(args)
#else
#define DLOG(args...)   /* */
#endif

struct descriptor_idt
{
    uint16_t offset_low;
    uint16_t seg_selector;
    uint8_t reserved;
    uint8_t flag;
    uint16_t offset_middle;
    uint32_t offset_high;
    uint32_t reserved2;
};

/* Borrowed from kernel source. It doesn't exist in Kernel.framework. */
struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};

kern_return_t PacketPID_start(kmod_info_t * ki, void *d);
kern_return_t PacketPID_stop(kmod_info_t *ki, void *d);
struct segment_command_64 *find_segment_64(struct mach_header_64 *mh, const char *segname);
struct load_command *find_load_command(struct mach_header_64 *mh, uint32_t cmd);
int find_symbol(struct mach_header_64 *mh, char *names[], void **sym_addrs[]);
uint64_t find_kernel_baseaddr( void );

extern uint64_t KERNEL_MH_START_ADDR;

#endif /* KernelResolver_h */
