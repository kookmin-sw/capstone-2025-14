#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
void initialize(void);
void alarm_handler(int signal);

int main(int argc, char *argv[])
{
 char buf[128];

 initialize();

 printf("buf = (%p)\n", buf);

 scanf("%141s", buf);

 return 0;
}

void initialize() {
 setvbuf(stdin, NULL, 2, 0);
 setvbuf(stdout, NULL, 2, 0);
 signal(14, alarm_handler);
 alarm(30);
}

void alarm_handler(int signal)
{
 puts("TIME OUT");
 exit(-1);
}

