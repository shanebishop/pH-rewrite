/*
This is an application for testing pH

#include <signal.h>
#include <time.h>

int timer_create(clock_t clockid, struct sigevent *sevp,
    timer_t *timerid);
    
#include <sys/types.h>
#include <unistd.h>

off_t lseek(int fd, off_t offset, int whence);
int _llseek(unsigned int fd, unsigned long offset_high,
    unsigned long offset_low, loff_t *result,
    unsigned int whence);

#include <sys/quota.h>
#include <xfs/xqm.h> // For XFS quotas

int quotactl(int cmd, const char *special, int id, caddr_t addr);
*/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

void main() {
    timer_t timerid;
    
    while (1) {
        sleep(1);
        printf("PID: %d\n", getpid();
    }
}
