#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <sys/user.h>

std::string s;

void child()
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    execl("/home/iv/os/debugger/hello", "hello", NULL);
}

void parent(pid_t pid)
{
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
    int status;
    waitpid(pid, &status, 0);

    while (!WIFEXITED(status))
    {
        struct user_regs_struct state;

        if (WIFSTOPPED(status) && (WSTOPSIG(status) & SIGTRAP))
        {
            ptrace(PTRACE_GETREGS, pid, 0, &state);
            printf("SYSCALL %lld at %llx\n", state.orig_rax, state.rip);


            if (state.orig_rax == 1)
            {
                char* text = (char*) state.rsi;
                ptrace(PTRACE_POKEDATA, pid, (void*) (text), 0x77207449);
                ptrace(PTRACE_POKEDATA, pid, (void*) (text + 4), 0x736b726f);
                ptrace(PTRACE_POKEDATA, pid, (void*) (text + 8), 0x00000a21);
            }
        }
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        waitpid(pid, &status, 0);
    }
}

int main()
{
    pid_t pid = fork();
    if (pid)
        parent(pid);
    else
        child();
    return 0;
}




