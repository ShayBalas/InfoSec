#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/reg.h>

int pid = 0x12345678;



int main(int argc, char **argv) {
    // Make the malware stop waiting for our output by forking a child process:
    
    int status;
    long original_eax;
    int insyscall = 0;
    struct user_regs_struct regs;

    if (fork() != 0) {
        // Kill the parent process so we stop waiting from the malware
        return 0;
    } else {
        // Close the output stream so we stop waiting from the malware
        fclose(stdout);
    }
    

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1){
        perror("attach");
        return -1;
    }

    while(1){
        
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)){
            return -1;
        }

        
        ptrace(PTRACE_SYSCALL, pid, 0,0);
        waitpid(pid, &status,0);

        ptrace(PTRACE_GETREGS, pid, 0 , &regs); //Get the syscall params
        original_eax = regs.orig_eax; //Get eax
        if (original_eax == SYS_read){ //if the syscall is read
            
            if(insyscall == 0){ //syscall entry
                insyscall = 1;
            }
            else{ //syscall exit
                regs.edx = 0;
                ptrace(PTRACE_SETREGS, pid, 0, &regs); //set edx to be 0
                insyscall = 0;
            }

        }

        ptrace(PTRACE_SYSCALL , pid, 0 ,0);
    }
    return 0;
}
