#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/user.h>
#include <vector>
#include <algorithm>
#include <iostream>

void trace(pid_t)
{
    //TODO
    //Здесь надо выполнять команды последовательно,
    //пока не встретим одну из списка breaks
    //подменять и возвращаться в основную программу
    //Я понимаю, как это делать

    /*ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);
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
    }*/
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

    std::vector<char*> breaks;
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
                breaks.push_back(ptr);
            } else {
                printf("Invalid argument for break");
            }
        } else if (strcmp(ptr, "clear") == 0) {
            ptr = strtok(NULL, " ");
            auto p = std::find(breaks.begin(), breaks.end(), ptr);
            if (p == breaks.end()) {
                printf("Invalid argument for clear");
            } else {
                breaks.erase(p);
            }
        } else if (strcmp(ptr, "run") == 0) {
            traced = atoi(argv[1]);
            ptrace(PTRACE_ATTACH, traced, NULL, NULL);
            attached = true;
            trace(traced);
        } else if (strcmp(ptr, "reg") == 0) {
            //TODO
            //печать регистров на текущий момент
            //Это я тоже понимаю
        } else if (strcmp(ptr, "mem") == 0) {
            //TODO
            //печать памяти на текущий момент
            //Это не понятно. Мехрубон? Рома?
        } else if (strcmp(ptr, "help") == 0) {
            //TODO
            //надо запилить список команд с описанием
        }
    }

    //g++ -std=c++14 -Wall -Wextra -Werror debugger.cpp
}
