---
title: SROP
date: 2025-10-26 23:34:19
categories: 
  - CTF技巧
tags:
  - CTF
  - pwn
  - SROP
---

拖了快半年了, 终于来把这个坑给填上.

# SROP

`SROP`全称`Sigreturn Oriented Programming,` 指利用Linux系统调用`rt_sigreturn`来进行ROP攻击的技术. 这种技术利用了sigreturn系统调用的特性, 允许攻击者通过构造特定的栈帧来控制寄存器的值, 从而实现任意代码执行.

虽说`SROP`被归类为高级ROP的一种, 但其实它的原理并不复杂. 主要是利用了`sigreturn`系统调用的机制, 在执行该系统调用时, 内核会从用户空间的栈中恢复寄存器的状态, 即将当前`$rsp`指向的一块区域视为所谓的`Signal Frame`, 然后将其中的内容加载到相应的寄存器中. 通过精心构造这个`Signal Frame`, 攻击者可以将所有寄存器设置为任意值。

对于`Signal Frame`来说，会因为架构的不同而有所区别，这里给出分别给出x86以及x64的sigcontext:

## x86 sigcontext

```c
struct sigcontext
{
  unsigned short gs, __gsh;
  unsigned short fs, __fsh;
  unsigned short es, __esh;
  unsigned short ds, __dsh;
  unsigned long edi;
  unsigned long esi;
  unsigned long ebp;
  unsigned long esp;
  unsigned long ebx;
  unsigned long edx;
  unsigned long ecx;
  unsigned long eax;
  unsigned long trapno;
  unsigned long err;
  unsigned long eip;
  unsigned short cs, __csh;
  unsigned long eflags;
  unsigned long esp_at_signal;
  unsigned short ss, __ssh;
  struct _fpstate * fpstate;
  unsigned long oldmask;
  unsigned long cr2;
};
```

## x64 sigcontext

```c
struct _fpstate
{
  /* FPU environment matching the 64-bit FXSAVE layout.  */
  __uint16_t        cwd;
  __uint16_t        swd;
  __uint16_t        ftw;
  __uint16_t        fop;
  __uint64_t        rip;
  __uint64_t        rdp;
  __uint32_t        mxcsr;
  __uint32_t        mxcr_mask;
  struct _fpxreg    _st[8];
  struct _xmmreg    _xmm[16];
  __uint32_t        padding[24];
};

struct sigcontext
{
  __uint64_t r8;
  __uint64_t r9;
  __uint64_t r10;
  __uint64_t r11;
  __uint64_t r12;
  __uint64_t r13;
  __uint64_t r14;
  __uint64_t r15;
  __uint64_t rdi;
  __uint64_t rsi;
  __uint64_t rbp;
  __uint64_t rbx;
  __uint64_t rdx;
  __uint64_t rax;
  __uint64_t rcx;
  __uint64_t rsp;
  __uint64_t rip;
  __uint64_t eflags;
  unsigned short cs;
  unsigned short gs;
  unsigned short fs;
  unsigned short __pad0;
  __uint64_t err;
  __uint64_t trapno;
  __uint64_t oldmask;
  __uint64_t cr2;
  __extension__ union
    {
      struct _fpstate * fpstate;
      __uint64_t __fpstate_word;
    };
  __uint64_t __reserved1 [8];
};
```

实际在利用中也不需要那么麻烦手动构造, `pwntools`中的`SigreturnFrame`类已经帮我们封装好了:

```python
from pwn import *
context.arch = 'amd64'  # or 'i386' for x86
sigframe = SigreturnFrame()
sigframe.rip = 0xdeadbeef  # Set the instruction pointer
sigframe.rsp = 0xdeadbeef  # Set the stack pointer
sigframe.rbp = 0xdeadbeef  # Set the base pointer
...
payload = bytes(sigframe)
```

通常我们会结合`syscall`指令来触发`sigreturn`系统调用. 在x86-64架构中, `syscall`指令的系统调用号为15, 一般需要先设法将`rax`寄存器设置为15(如利用read函数返回值), 然后rop到`syscall`指令执行, 栈后面紧跟着构造好的`Signal Frame`, 这样在`syscall`结束时内核就会将寄存器设置为我们指定的值.

# SROP chain

通过`SROP`技术, 我们还可以构造`SROP chain`, 也就是一系列的`Signal Frame`, 其中每个`Signal Frame`的`$rsp`都指向下一个`Signal Frame`. 这样在执行完第一个`sigreturn`后, 内核会将`$rsp`设置为下一个`Signal Frame`, 然后再次执行`sigreturn`, 以此类推.

最后, 需要注意的是, `SROP`的`Signal Frame`结构体需要的空间较大(在x64上需要0xf8字节, 加上触发`syscall`的gadget恰好为0x100字节), 因此在利用时需要确保有足够的空间来存放这些数据. 
