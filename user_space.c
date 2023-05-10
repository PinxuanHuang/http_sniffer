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
    struct ft ft_info;
    int my_dev = open("/dev/" DEV_NAME, O_RDWR | O_SYNC);

    if (my_dev == -1)
    {
        printf("Fail to open your file descriptor %d\n", errno);
        goto DEV_FAIL;
    }

    if (ioctl(my_dev, SET_TO_USER, &ft_info) < 0)
    {
        goto IO_FAIL;
    }

    printf("sip: %u.%u.%u.%u, dip: %u.%u.%u.%u\n",
           ft_info.sip[0],
           ft_info.sip[1],
           ft_info.sip[2],
           ft_info.sip[3],
           ft_info.dip[0],
           ft_info.dip[1],
           ft_info.dip[2],
           ft_info.dip[3]);

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
