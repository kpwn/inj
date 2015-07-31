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
    void* rop_page = libinj_copyout(inj, &gadgets, &end_gadgets - &gadgets);

    char* str = malloc(2048);
    bzero(str, 2048);
    strcpy(str+128, argv[2]);
    void* str_page = libinj_copyout(inj, str, 2048);
    struct mach_header *hdr = libinj_main_header(inj);
    if(hdr->magic == MH_MAGIC_64) {
        uint64_t stack [4096];
        
        bzero(stack, sizeof(stack));
        
        int ctr=3600;
        
        stack[ctr++] = F(ROP_POP_RDI, rop_page); // in a mach thread now, all selectors NULL
        stack[ctr++] = (uint64_t) str_page + 1536; // arg1
        
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
        
        stack[ctr++] = F(ROP_POP_RDI, rop_page); // in a pthread now (with %gs set!)
        stack[ctr++] = (uint64) str_page+128;
        
        stack[ctr++] = F(ROP_POP_RSI, rop_page);
        stack[ctr++] = RTLD_LAZY;
        
        stack[ctr++] = S(inj, "_dlopen");
        
        stack[ctr++] = F(ROP_RET, rop_page); // align
        stack[ctr++] = S(inj, "_pthread_exit");
        
        void* remote_stack = libinj_copyout(inj, stack, sizeof(stack));
        
        vm_protect(inj, (vm_address_t)remote_stack, sizeof(stack), 0, PROT_READ | PROT_WRITE);
        vm_protect(inj, (vm_address_t)rop_page, (&end_gadgets - &gadgets), 0, PROT_READ | PROT_EXEC);
        
        mach_port_t remote_thread_port = libinj_create_thread(inj, remote_stack + (3600 * sizeof(uint64_t)), rop_page);
        printf("[+] injected a 64 bit task, cleaning up.. ");
        sleep(1);
        thread_abort(remote_thread_port);
        puts("done");
    } else {
        // gadgets are the same for both 64 and 32 bit intel x86
        uint32_t stack [4096];
        
        bzero(stack, sizeof(stack));
        
        int ctr=2000;
        stack[ctr++] = (uint32) F(ROP_HUNT_REPLACE_200H_RSP, rop_page);
        stack[ctr++] = (uint32) S(inj, "_pthread_create");
        stack[ctr++] = (uint32) F(ROP_HANG, rop_page); // hang and wait to be killed

        stack[ctr++] = (uint32) str_page; //F(ROP_ADD200H_RCX, rop_page); // arg4
        stack[ctr++] = (uint32) 0; // arg2
        stack[ctr++] = (uint32) F(ROP_POP_POP_RSP, rop_page); // arg2
        stack[ctr++] = (uint32) 0x44444444; // arg2
        
        for (int i=0; i<0x220/4; i++) {
            stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        }
        
        
        stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        stack[ctr++] = (uint32) F(ROP_RET, rop_page);
        stack[ctr++] = (uint32)S(inj, "_dlopen");
        stack[ctr++] = (uint32)S(inj, "_pthread_exit");
        stack[ctr++] = (uint32) str_page+128;
        stack[ctr++] = RTLD_LAZY;
        
        
        void* remote_stack = libinj_copyout(inj, stack, sizeof(stack));
        
        vm_protect(inj, (vm_address_t)remote_stack, sizeof(stack), 0, PROT_READ | PROT_WRITE);
        vm_protect(inj, (vm_address_t)rop_page, (&end_gadgets - &gadgets), 0, PROT_READ | PROT_EXEC);
        mach_port_t remote_thread_port = libinj_create_thread(inj, remote_stack + (2000 * 4), rop_page);
        printf("[+] injected a 32 bit task, cleaning up.. ");
        sleep(1);
        thread_abort(remote_thread_port);
        puts("done");
    }
    return 0;
}
