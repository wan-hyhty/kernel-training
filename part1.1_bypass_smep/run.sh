#!/bin/sh
qemu-system-x86_64 \
    -m 128M\
    -cpu kvm64,+smap,+smep \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 nokaslr nopti quiet panic=1" \
    -s