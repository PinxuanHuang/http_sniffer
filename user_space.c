#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "self_define.h"

int main()
{
    // struct ft ft_info;
    int my_dev = open("/dev/" DEV_NAME, O_RDWR | O_SYNC);

    if (my_dev == -1)
    {
        printf("Fail to open your file descriptor %d\n", errno);
        goto DEV_FAIL;
    }
    // TODO convert the ft info into pcap format

IO_FAIL:
    if (my_dev)
    {
        // ???
        close(my_dev);
        my_dev = 0;
    }
DEV_FAIL:
    return 0;
}
