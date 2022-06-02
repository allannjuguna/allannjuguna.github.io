---
layout: post
category : images
title: Disk-Images!
---

## Image files

We have a file named `demo.zip`. Running the file command on it we get the following output.

<div class="highlight-code">

<code>➤ allan: /tmp $ file demo.bin</code>
<code>demo.bin: u-boot legacy uImage, jz_fw, Linux/MIPS, Firmware Image (Not compressed), 11075584 bytes, Thu Aug 20 11:05:28 2020, Load Address: 0x00000000, Entry Point: 0x00000000, Header CRC: 0x8BBFA81F, Data CRC: 0x80B3509C</code><br/>
</div>

## What is the size of the kernel
u-boot uImage files have a 64-byte header defined in image.h as follows:

<div class="highlight-code">

<code>#define IH_MAGIC&nbsp;&nbsp;&nbsp;0x27051956&nbsp;&nbsp;&nbsp;/* Image Magic Number&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>#define IH_NMLEN&nbsp;&nbsp;&nbsp;32&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Name Length&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code></code><br/>
<code>typedef struct image_header {</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_magic;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Header Magic Number */</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_hcrc;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Header CRC Checksum */</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_time;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Creation Timestamp&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_size;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Data Size&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_load;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Data&nbsp;&nbsp;&nbsp;Load&nbsp;&nbsp;&nbsp;Address&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_ep;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Entry Point Address&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint32_t&nbsp;&nbsp;&nbsp;ih_dcrc;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Data CRC Checksum&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint8_t&nbsp;&nbsp;&nbsp;ih_os;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Operating System&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint8_t&nbsp;&nbsp;&nbsp;ih_arch;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* CPU architecture&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint8_t&nbsp;&nbsp;&nbsp;ih_type;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Image Type&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint8_t&nbsp;&nbsp;&nbsp;ih_comp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;/* Compression Type&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>uint8_t&nbsp;&nbsp;&nbsp;ih_name[IH_NMLEN];&nbsp;&nbsp;&nbsp;/* Image Name&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;*/</code><br/>
<code>} image_header_t;</code><br/>
</div>



Running binwalk on the file we get the following output

<div class="highlight-code">
<code>➤ allan: /tmp $ binwalk demo.bin</code><br/>
<code></code><br/>
<code>DECIMAL&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HEXADECIMAL&nbsp;&nbsp;&nbsp;DESCRIPTION</code><br/>
<code>--------------------------------------------------------------------------------</code><br/>
<code>0&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x0&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;uImage header, header size: 64 bytes, header CRC: 0x8BBFA81F, created: 2020-08-20 11:05:28, image size: 11075584 bytes, Data Address: 0x0, Entry Point: 0x0, data CRC: 0x80B3509C, OS: Linux, CPU: MIPS, image type: Firmware Image, compression type: none, image name: "jz_fw"</code><br/>
<code>64&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x40&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;uImage header, header size: 64 bytes, header CRC: 0x6F5948F4, created: 2020-05-26 05:03:55, image size: 1907357 bytes, Data Address: 0x80010000, Entry Point: 0x80421870, data CRC: 0xD8FCDDFA, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux-3.10.14"</code><br/>
<code>128&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x80&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: -1 bytes</code><br/>
<code>2097216&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x200040&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Squashfs filesystem, little endian, version 4.0, compression:xz, size: 3289960 bytes, 414 inodes, blocksize: 131072 bytes, created: 2020-08-20 09:14:53</code><br/>
<code>5570624&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x550040&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Squashfs filesystem, little endian, version 4.0, compression:xz, size: 593566 bytes, 13 inodes, blocksize: 131072 bytes, created: 2020-08-20 09:14:54</code><br/>
<code>6225984&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;0x5F0040&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JFFS2 filesystem, little endian</code><br/>
</div>


Previously we saw that the first 64 bytes of a uImage file contain the header info , so we skip that part. The next line (0x64) contains the Kernel Image header which is 64 bytes and runs upto 0x128 then the LZMA compressed data which runs upto 2097216. The kernel is a combination of the OS kernel Image header and the LZMA compressed data, so to get its size we need to calculate 2097216 - 64, which is 2097152


## What are the names of the backup files in the first root filesystem
We can assume that the first root filesystem is the first squashfs block we see, we need to extract.
Since it runs from 2097216 to 5570624 meaning it is 3473408 bytes in size. We will use the following dd command to extract it 

<div class="highlight-code">
<code>dd if=demo.bin of=squashfs skip=2097216 count=3473408 bs=1</code><br/>
</div>

The result is 
<div class="highlight-code">
<code>➤ allan: /tmp $ dd if=demo.bin of=squashfs skip=2097216 count=3473408 bs=1</code><br/>
<code>3473408+0 records in</code><br/>
<code>3473408+0 records out</code><br/>
<code>3473408 bytes (3.5 MB, 3.3 MiB) copied, 10.0029 s, 347 kB/s</code><br/>
</div>


Running file command on the file we can confirm it is a squashfs file
<div class="highlight-code">
<code>➤ allan: /tmp $ file squashfs</code><br/>
<code>squashfs: Squashfs filesystem, little endian, version 4.0, 3289960 bytes, 414 inodes, blocksize: 131072 bytes, created: Thu Aug 20 09:14:53 2020</code><br/>
</div>


Mounting the file to a temporary mount point
<div class="highlight-code">
<code>➤ allan: /tmp $ mkdir -p mntpnt ; sudo mount -t squashfs squashfs mntpnt/</code><br/>
<code>➤ allan: /tmp $ cd mntpnt/</code><br/>
<code>➤ allan: /tmp/mntpnt $ ls</code><br/>
<code>backupa&nbsp;&nbsp;&nbsp;bin&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;driver&nbsp;&nbsp;&nbsp;linuxrc&nbsp;&nbsp;&nbsp;opt&nbsp;&nbsp;&nbsp;root&nbsp;&nbsp;&nbsp;sys&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;tmp</code><br/>
<code>backupd&nbsp;&nbsp;&nbsp;configs&nbsp;&nbsp;&nbsp;etc&nbsp;&nbsp;&nbsp;media&nbsp;&nbsp;&nbsp;params&nbsp;&nbsp;&nbsp;run&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;system&nbsp;&nbsp;&nbsp;usr</code><br/>
<code>backupk&nbsp;&nbsp;&nbsp;dev&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;lib&nbsp;&nbsp;&nbsp;mnt&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;proc&nbsp;&nbsp;&nbsp;sbin&nbsp;&nbsp;&nbsp;thirdlib&nbsp;&nbsp;&nbsp;var</code><br/>
<code></code><br/>
</div>


The backup folders are backupa backupd and backupk


## What is the name of the root folder of the developer

## References

- https://ctf.rip/write-ups/iot/firmware/wormcon-firm/
- https://linux.die.net/man/1/mkimage
- http://www.techpository.com/linux-unpacking-and-repacking-u-boot-uimage-files/
- https://patrickrbc.com/2019/06/02/re-wireless-repeater-2
- https://reverseengineering.stackexchange.com/questions/20632/help-unpacking-u-boot-firmware