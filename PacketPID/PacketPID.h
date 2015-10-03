//
//  PacketPID kernel extension
//
//  Created by huangyan13@baidu.com on 15/9/30.
//  Copyright © 2015 Baidu Inc. All rights reserved.
//

#ifndef PacketPID_h
#define PacketPID_h

/*
 * Socket process information
 */
struct so_procinfo {
    pid_t		spi_pid;
    pid_t		spi_epid;
    uuid_t		spi_uuid;
    uuid_t		spi_euuid;
};


#define IFACE_BUFFER_SIZE 16



#endif /* PacketPID_h */
