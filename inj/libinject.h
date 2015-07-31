//
//  libinject.h
//  inj
//
//  Created by qwertyoruiop on 31/07/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//

#ifndef __inj__libinject__
#define __inj__libinject__
#import <Foundation/Foundation.h>

#include <stdio.h>
#include <sys/types.h>
typedef mach_port_t inject_t;
inject_t libinj_inject_pid (pid_t pid);
mach_port_t libinj_create_thread (inject_t inj, unsigned long* stack, void* initial_instr);
void* libinj_find_symbol(inject_t inj, char* name);
void libinj_find_regions(inject_t inj);
struct mach_header* libinj_main_header(inject_t inj);
void* libinj_copyout(inject_t inj, void* data, size_t size);
#endif /* defined(__inj__libinject__) */
