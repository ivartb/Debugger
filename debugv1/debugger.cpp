#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <vector>
#include <algorithm>
#include <iostream>

std::vector<long long> breaks;
char code[] = {(char)0xcd, (char)0x80, (char)0xcc, (char)0};
char backup[4];
bool is_stopped = false;
int status;

const int long_size = sizeof(long long);
void getdata(pid_t child, long long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void putdata(pid_t child, long long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long long val;
            char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if(j != 0) {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i * 4, data.val);
    }
}

void trace(pid_t pid)
{
    struct user_regs_struct regs;

    if (is_stopped) {
        is_stopped = false;
        putdata(pid, regs.rip, backup, 3);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);
    }

    while (!WIFEXITED(status))
    {
        if (WIFSTOPPED(status) && (WSTOPSIG(status) & SIGTRAP))
        {
            ptrace(PTRACE_GETREGS, pid, 0, &regs);

            auto p = std::find(breaks.begin(), breaks.end(), regs.orig_rax);
            if (p != breaks.end()) {
                getdata(pid, regs.rip, backup, 3);
                putdata(pid, regs.rip, code, 3);
                ptrace(PTRACE_CONT, pid, NULL, NULL);
                waitpid(pid, &status, 0);
                printf("Process stopped by SYSCALL %llx at %llx\n", regs.orig_rax, regs.rip);
                is_stopped = true;
                break;
            }
        }
        ptrace(PTRACE_CONT, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
}

void trace_step(pid_t pid)
{
    struct user_regs_struct regs;

    if (is_stopped) {
        is_stopped = false;
        putdata(pid, regs.rip, backup, 3);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }
    ptrace(PTRACE_CONT, pid, 0, 0);
    waitpid(pid, &status, 0);
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    printf("SYSCALL %llx at %llx\n", regs.orig_rax, regs.rip);
}

void print_regs(pid_t pid, char* reg)
{
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, 0, &regs);
    if (strcmp(reg, "r15") == 0) printf("r15 = %llx", regs.r15);
    else if (strcmp(reg, "r14") == 0) printf("r14 = %llx", regs.r14);
    else if (strcmp(reg, "r13") == 0) printf("r13 = %llx", regs.r13);
    else if (strcmp(reg, "r12") == 0) printf("r12 = %llx", regs.r12);
    else if (strcmp(reg, "rbp") == 0) printf("rbp = %llx", regs.rbp);
    else if (strcmp(reg, "rbx") == 0) printf("rbx = %llx", regs.rbx);
    else if (strcmp(reg, "r11") == 0) printf("r11 = %llx", regs.r11);
    else if (strcmp(reg, "r10") == 0) printf("r10 = %llx", regs.r10);
    else if (strcmp(reg, "r9") == 0) printf("r9 = %llx", regs.r9);
    else if (strcmp(reg, "r8") == 0) printf("r8 = %llx", regs.r8);
    else if (strcmp(reg, "rax") == 0) printf("rax = %llx", regs.rax);
    else if (strcmp(reg, "rcx") == 0) printf("rcx = %llx", regs.rcx);
    else if (strcmp(reg, "rdx") == 0) printf("rdx = %llx", regs.rdx);
    else if (strcmp(reg, "rsi") == 0) printf("rsi = %llx", regs.rsi);
    else if (strcmp(reg, "rdi") == 0) printf("rdi = %llx", regs.rdi);
    else if (strcmp(reg, "orig_rax") == 0) printf("orig_rax = %llx", regs.orig_rax);
    else if (strcmp(reg, "rip") == 0) printf("rip = %llx", regs.rip);
    else if (strcmp(reg, "cs") == 0) printf("cs = %llx", regs.cs);
    else if (strcmp(reg, "eflags") == 0) printf("eflags = %llx", regs.eflags);
    else if (strcmp(reg, "rsp") == 0) printf("rsp = %llx", regs.rsp);
    else if (strcmp(reg, "ss") == 0) printf("ss = %llx", regs.ss);
    else if (strcmp(reg, "fs_base") == 0) printf("fs_base = %llx", regs.fs_base);
    else if (strcmp(reg, "gs_base") == 0) printf("gs_base = %llx", regs.gs_base);
    else if (strcmp(reg, "ds") == 0) printf("ds = %llx", regs.ds);
    else if (strcmp(reg, "es") == 0) printf("es = %llx", regs.es);
    else if (strcmp(reg, "fs") == 0) printf("fs = %llx", regs.fs);
    else if (strcmp(reg, "gs") == 0) printf("gs = %llx", regs.gs);
    else printf("Invalid register");

}

int main(int argc, char* argv[])
{
    pid_t traced;
    bool attached = false;

    if (argc != 2)
    {
        printf("Usage: %s <pid to be traced>\n", argv[0]);
        return -1;
    }

    traced = atoi(argv[1]);
    ptrace(PTRACE_ATTACH, traced, NULL, NULL);
    attached = true;
    waitpid(traced, &status, 0);
    printf("Process attached\n");


    std::string command;
    while (true)
    {
        std::cin >> command;
        char* ptr;
        ptr = strtok(const_cast<char*>(command.c_str()), " ");
        if (strcmp(ptr, "quit") == 0) {
            if (attached) {
                ptrace(PTRACE_DETACH, traced, NULL, NULL);
            }
            return 0;
        } else if (strcmp(ptr, "break") == 0) {
            ptr = strtok(NULL, " ");
            if (ptr != NULL) {
                breaks.push_back(atoll(ptr));
                printf("Breakpoint set at %llx", atoll(ptr));
            } else {
                printf("Invalid argument for break\n");
            }
        } else if (strcmp(ptr, "clear") == 0) {
            ptr = strtok(NULL, " ");
            auto p = std::find(breaks.begin(), breaks.end(), atoll(ptr));
            if (p == breaks.end()) {
                printf("Invalid argument for clear\n");
            } else {
                breaks.erase(p);
                printf("Breakpoint deleted at %llx", atoll(ptr));
            }
        } else if (strcmp(ptr, "run") == 0) {
            printf("Process %d is starting\n", traced);
            trace(traced);
        } else if (strcmp(ptr, "continue") == 0) {
            if (is_stopped) {
                trace(traced);
            } else {
                printf("Process is not runnig now. Use: run\n");
            }
        } else if (strcmp(ptr, "next") == 0) {
            trace_step(traced);
        } else if (strcmp(ptr, "reg") == 0) {
            ptr = strtok(NULL, " ");
            print_regs(traced, ptr);
        } else if (strcmp(ptr, "mem") == 0) {
            //TODO
            //печать памяти на текущий момент
            //Это не понятно. Мехрубон? Рома?
        } else if (strcmp(ptr, "help") == 0) {
            printf("break <SYSCALL>     - Set a breakpoint at SYSCALL\n");
            printf("clear <SYSCALL>     - Delete a breakpoint from SYSCALL\n");
            printf("continue            - Continues the stopped process\n");
            printf("help                - Prints this help message\n");
            printf("mem <address>       - Prints memory at address\n");
            printf("next                - Do next step\n");
            printf("reg <register>      - Prints register\n");
            printf("run                 - Start the process\n");
            printf("quit                - Exit the programm\n");
        } else {
            printf("Invalid command. See help.\n");
        }
    }

    // g++ -std=c++14 -Wall -Wextra -Werror debugger.cpp -o debugger
    // gcc hello.c -o hello
    // ./hello &
    // ./debugger <pid of hello>
}

/*
 0x0000000000400546 <+0>:	push   %rbp
   0x0000000000400547 <+1>:	mov    %rsp,%rbp
   0x000000000040054a <+4>:	mov    $0xa,%edi
   0x000000000040054f <+9>:	mov    $0x0,%eax
   0x0000000000400554 <+14>:	callq  0x400440 <sleep@plt>
   0x0000000000400559 <+19>:	mov    $0xe,%edx
   0x000000000040055e <+24>:	mov    $0x400604,%esi
   0x0000000000400563 <+29>:	mov    $0x1,%edi
   0x0000000000400568 <+34>:	mov    $0x0,%eax
   0x000000000040056d <+39>:	callq  0x400410 <write@plt>
   0x0000000000400572 <+44>:	mov    $0x0,%eax
   0x0000000000400577 <+49>:	pop    %rbp
   0x0000000000400578 <+50>:	retq



SYSCALL 219 at 7f4238452f10
SYSCALL 219 at 7f4238452f10
SYSCALL 1 at 7f4238474c00
It works!
SYSCALL 1 at 7f4238474c00
SYSCALL 231 at 7f42384532e9

*/












