//
//  main.m
//  inj
//
//  Created by qwertyoruiop on 31/07/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//


//  on the fly & runtime injection tool (64 bit only now, 32 support coming #of#soon)

#import <Foundation/Foundation.h>
#include "libinject.h"
#include <dlfcn.h>


extern char gadgets;

extern char ROP_RET;
extern char ROP_POP_RDI;
extern char ROP_POP_RSI;
extern char ROP_POP_RDX;
extern char ROP_POP_RCX;
extern char ROP_POP_RAX;
extern char ROP_POP_POP_RAX;
extern char ROP_WRITE_RAX_TO_RDI;
extern char ROP_READ_RAX_TO_RDI;
extern char ROP_POP_POP_RSP;
extern char ROP_HUNT_REPLACE_200H_RSP;
extern char ROP_RSP_TO_RCX;
extern char ROP_RAX_TO_RDI;
extern char ROP_RDI_TO_RSP;
extern char ROP_ADD200H_RCX;
extern char ROP_HANG;

extern char end_gadgets;

char die(char* x) {
    puts(x);
    exit(-1);
}

#define F(gd, page) (uint64_t)((&gd-&gadgets)+page)
#define S(inj, nm) (uint64_t)(libinj_find_symbol(inj, nm))
int main(int argc, const char * argv[]) {
    if (argc < 3) {
        puts("usage: inj [pid] [dylib]");
        return -1;
    }
    inject_t inj = libinj_inject_pid(atoi(argv[1]));
    if(!inj) {
        return -1;
    }
    void* rop_page = libinj_copyout(inj, &gadgets, &end_gadgets - &gadgets);
    void* str_page = libinj_copyout(inj, (void*)argv[2], strlen(argv[2])+1);
    struct mach_header *hdr = libinj_main_header(inj);
    if(hdr->magic == MH_MAGIC_64) {
        mach_vm_address_t remote_stack = 0;
        uint64_t *stack = libinj_map_mem(inj, 4096*sizeof(uint64_t), &remote_stack);
        if (!stack) {
            exit(-1);
        }
        bzero(stack, sizeof(stack));
        
        int ctr=3600, sctr=0;
        stack[ctr++] = S(inj, "_mach_thread_self");
        stack[ctr++] = F(ROP_POP_RDI, rop_page);
        stack[ctr  ] = (remote_stack);
        sctr = ctr; ctr++;
        stack[ctr++] = F(ROP_WRITE_RAX_TO_RDI, rop_page);
        
        stack[ctr++] = F(ROP_POP_RDI, rop_page); // in a mach thread now, all selectors NULL
        stack[ctr++] = (uint64_t) str_page + 4088;
        stack[ctr++] = F(ROP_POP_RSI, rop_page);
        stack[ctr++] = 0; // arg2
        
        stack[ctr++] = F(ROP_POP_RDX, rop_page);
        stack[ctr++] = F(ROP_RDI_TO_RSP, rop_page); // arg3
        
        stack[ctr++] = F(ROP_RSP_TO_RCX, rop_page);
        stack[ctr++] = F(ROP_ADD200H_RCX, rop_page); // arg4
        
        stack[ctr++] = S(inj, "_pthread_create");
        stack[ctr++] = F(ROP_HANG, rop_page); // hang and wait to be killed
        
        ctr += 0x1A0/8;
        for (int i=0; i<0x20; i++) {
            stack[ctr++] = F(ROP_RET, rop_page);
        }
        
        stack[ctr++] = F(ROP_POP_RDI, rop_page); // return
        stack[ctr]   = 0;
        stack[sctr] += (ctr * sizeof(uint64_t));
        ctr++;
        stack[ctr++] = S(inj, "_thread_terminate");
        stack[ctr++] = F(ROP_RET, rop_page);

        stack[ctr++] = F(ROP_POP_RDI, rop_page); // in a pthread now (with %gs set!)
        stack[ctr++] = (uint64) str_page;
        
        stack[ctr++] = F(ROP_POP_RSI, rop_page);
        stack[ctr++] = RTLD_LAZY;
        
        stack[ctr++] = S(inj, "_dlopen");
        stack[ctr++] = F(ROP_RET, rop_page); // align
        
        stack[ctr++] = F(ROP_POP_RDI, rop_page);
        stack[ctr++] = (uint64_t) (remote_stack);
        
        stack[ctr++] = F(ROP_POP_RAX, rop_page); // return
        stack[ctr++] = 0xF1F2F3F4;
        stack[ctr++] = F(ROP_POP_RDI, rop_page);
        stack[ctr++] = (remote_stack);
        stack[ctr++] = F(ROP_WRITE_RAX_TO_RDI, rop_page);
        
        stack[ctr++] = S(inj, "_pthread_exit");
        
        vm_protect(inj, (vm_address_t)rop_page, (&end_gadgets - &gadgets), 0, PROT_READ | PROT_EXEC);
        
        libinj_create_thread(inj, (void*)remote_stack + (3600 * sizeof(uint64_t)), rop_page);
        
        printf("[+] injected a 64 bit task, cleaning up.. ");
        
        fflush(stdout);
        
        while (1) {
            if (stack[0] == 0xF1F2F3F4) {
                vm_deallocate(inj, (vm_address_t)remote_stack, 4096*sizeof(uint64_t));
                vm_deallocate(inj, (vm_address_t)rop_page,  (&end_gadgets - &gadgets));
                vm_deallocate(inj, (vm_address_t)str_page, 4096);
                break;
            }
            usleep(10000);
        }
        
        puts("done");
        
    } else {
        // gadgets are the same for both 64 and 32 bit intel x86
        mach_vm_address_t remote_stack=0;
        uint32_t *stack = libinj_map_mem(inj, 4096*sizeof(uint32_t), &remote_stack);
        
        bzero(stack, sizeof(stack));
        
        int ctr=2000;
        int sctr = 0;
        stack[ctr++] = (uint32) S(inj, "_mach_thread_self");
        stack[ctr++] = (uint32) F(ROP_POP_RDI, rop_page);
        stack[ctr  ] = (uint32) (remote_stack);
        sctr = ctr; ctr++;
        stack[ctr++] = (uint32) F(ROP_WRITE_RAX_TO_RDI, rop_page) + 1; // 64 bit op has 1 additional byte which decreases eax by 1, breaking this (but not a problem on other stuff)
        
        stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        stack[ctr++] = (uint32) S(inj, "_pthread_create");
        stack[ctr++] = (uint32) F(ROP_HANG, rop_page); // hang and wait to be killed

        stack[ctr++] = (uint32) str_page+4088; //F(ROP_ADD200H_RCX, rop_page); // arg4
        stack[ctr++] = (uint32) 0; // arg2
        stack[ctr++] = (uint32) F(ROP_POP_POP_RSP, rop_page); // arg2
        stack[ctr++] = (uint32) remote_stack+ (2000 * 4)+0x200; // arg2
        
        for (int i=0; i<0x220/4; i++) {
            stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        }
        
        stack[ctr++] = (uint32) S(inj, "_thread_terminate");
        stack[ctr++] = (uint32) F(ROP_POP_RAX, rop_page); // return
        stack[ctr]   = 0;
        stack[sctr] += (uint32) (ctr * sizeof(uint32));
        ctr++;

        stack[ctr++] = (uint32)S(inj, "_dlopen");
        stack[ctr++] = (uint32)F(ROP_POP_POP_RAX, rop_page);
        stack[ctr++] = (uint32) str_page;
        stack[ctr++] = RTLD_LAZY;
        
        stack[ctr++] = (uint32) F(ROP_POP_RAX, rop_page); // return
        stack[ctr++] = (uint32) 0xF1F2F3F4;
        stack[ctr++] = (uint32) F(ROP_POP_RDI, rop_page);
        stack[ctr++] = (uint32) (remote_stack);
        stack[ctr++] = (uint32) F(ROP_WRITE_RAX_TO_RDI, rop_page) + 1; // 64 bit op has 1 additional byte which decreases eax by 1, breaking this (but not a problem on other stuff)

        stack[ctr++] = (uint32)S(inj, "_pthread_exit");

        vm_protect(inj, (vm_address_t)rop_page, (&end_gadgets - &gadgets), 0, PROT_READ | PROT_EXEC);
        
        libinj_create_thread(inj, (void*)remote_stack + (2000 * 4), rop_page);
        
        printf("[+] injected a 32 bit task, cleaning up.. ");
        
        fflush(stdout);
        
        while (1) {
            
            if (stack[0] == 0xF1F2F3F4) {
                
                vm_deallocate(inj, (vm_address_t)remote_stack, 4096*sizeof(uint32_t));
                vm_deallocate(inj, (vm_address_t)rop_page,  (&end_gadgets - &gadgets));
                vm_deallocate(inj, (vm_address_t)str_page, 4096);
                break;
                
            }
            
            usleep(10000);
            
        }
        
        puts("done");
    }
    return 0;
}
