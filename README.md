# FLARE

This is the PoC implementation for the AsiaCCS'20 paper
[KASLR: Break It, Fix It, Repeat](http://cc0x1f.net/publications/kaslr.pdf) by Canella, Schwarz, Haubenwallner, Schwarzl and Gruss

## Description

FLARE is a Linux kernel module implementing a mitigation for microarchitectural KASLR breaks like Data Bounce, Prefetch side channel, DrK, and so on. Using dummy mappings in the kernel address space, we mitigate the root cause behind these microarchitectural KASLR breaks by solving three challenges:

* Eliminating the differences in timing and behavior of mapped and unmapped pages.
* Eliminating timing differences depending on page sizes.
* Eliminating the timing difference between executable and non-executable pages.

Currently, FLARE is implemented for both kernel text and module segment, although the module segment requires additional modifications that have to be implemented directly in the kernel to mitigate all currently known microarchitectural attacks fully.

**For a short video of Data Bounce and EchoLoad and how FLARE mitigates them, watch the demo video 'flare.mp4'**

[![Watch the demo](https://raw.github.com/flare-mitigation/FLARE/master/flare.png)](https://github.com/flare-mitigation/FLARE/raw/master/flare.mp4)

### Prerequisites
The capability to build kernel modules and loading them.

To build the module, the following packages are required:
```
sudo apt-get install gcc make linux-headers-$(uname -r)
```

### Usage
Build the kernel module by running
```
make
```

After successfully building it, load it by running
```
sudo insmod flare.ko
```

Remove the module by running
```
sudo rmmod flare
```

#### Warnings
**Warning #1**: We are providing this code as-is. You are responsible for protecting yourself, your property and data, and others from any risks caused by this code. This code may cause unexpected and undesirable behavior to occur on your machine.

**Warning #2**: This code is only for testing purposes. Do not run it on any productive systems. Do not run it on any system that might be used by another person or entity.
