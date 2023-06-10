#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/ioctl.h>

#include "self_define.h"

static int keep_running = 1; /* the flag to control the process */

void handler(int dummy)
{
    keep_running = 0;
}

FILE *write_pcap_file(char *file_name)
{
    int res = 0;
    FILE *pcap_file = NULL;
    pcap_hdr_t pcaph =
        {
            .magic_number = 0xa1b2c3d4,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = 65535,
            .network = 1,
        };
    // printf("step1\n");
    pcap_file = fopen(file_name, "w");
    if (pcap_file == NULL)
    {
        return NULL;
    }
    // printf("step2\n");
    res = fwrite((char *)&pcaph, sizeof(pcap_hdr_t), 1, pcap_file);
    /* Error in writing file */
    if (res != 1)
    {
        fclose(pcap_file);
        return NULL;
    }
    // printf("step3\n");
    fflush(pcap_file);
    return pcap_file;
}

int main()
{
    signal(SIGINT, handler);
    int res = 0;
    int packet_counter = 0;
    pcaprec_hdr_t pcaprec_hdr;
    FILE *pcap_file = NULL;
    char *file_name = "my_pcap.pcap";

    struct packet_data pkt_data = {0};
    int my_dev = open("/dev/" DEV_NAME, O_RDWR | O_SYNC);

    if (my_dev == -1)
    {
        printf("Fail to open your file descriptor %d\n", errno);
        goto DEV_FAIL;
    }
    /*
    TODO
    create the pcap file
    */
    pcap_file = write_pcap_file(file_name);
    printf("Success to open file my_pcap.pcap\n");

    while (keep_running)
    {
        if (ioctl(my_dev, SET_TO_USER, &pkt_data) == 0)
        {
            if (pkt_data.payload_len != 0)
            {
                pcaprec_hdr = (pcaprec_hdr_t){
                    .ts_sec = 1686143029,
                    .ts_usec = 100,
                    .incl_len = pkt_data.payload_len,
                    .orig_len = pkt_data.payload_len,
                };
                printf("packet data length : %d\n", pkt_data.payload_len);
                res = fwrite((char *)&pcaprec_hdr, sizeof(pcaprec_hdr_t), 1, pcap_file);
                if (res != 1)
                {
                    goto IO_FAIL;
                }
                printf("Success to write packet hdr in my_pcap.pcap\n");
                res = fwrite(pkt_data.payload, pkt_data.payload_len, 1, pcap_file);
                if (res != 1)
                {
                    goto IO_FAIL;
                }
                printf("[Get a packet] final 5 bytes of the packet %u %u %u %u %u", pkt_data.payload[pkt_data.payload_len - 5], pkt_data.payload[pkt_data.payload_len - 4], pkt_data.payload[pkt_data.payload_len - 3], pkt_data.payload[pkt_data.payload_len - 2], pkt_data.payload[pkt_data.payload_len - 1]);
                memset(&pkt_data, 0, sizeof(struct packet_data));
                packet_counter = packet_counter + 1;
            }
        }
    }
    printf("There's %d packets\n", packet_counter);
IO_FAIL:
    if (my_dev)
    {
        close(my_dev);
        my_dev = 0;
    }
DEV_FAIL:
    fclose(pcap_file);
    return 0;
}
