#include <stddef.h>
#ifndef _SELF_DEFINE_H_
#define _SELF_DEFINE_H_

#define DEV_NAME "simple_dev"
#define MAP_SIZE 10

/* pcap file global header structure */
typedef struct pcap_hdr_s
{
    unsigned int magic_number;  /* magic number */
    unsigned int version_major; /* major version number */
    unsigned int version_minor; /* minor version number */
    int thiszone;               /* GMT to local correction */
    unsigned int sigfigs;       /* accuracy of timestamps */
    unsigned int snaplen;       /* max length of captured packets, in octets */
    unsigned int network;       /* data link type */
} pcap_hdr_t;

/* pcap file packet header structure */
typedef struct pcaprec_hdr_s
{
    unsigned int ts_sec;   /* timestamp seconds */
    unsigned int ts_usec;  /* timestamp microseconds */
    unsigned int incl_len; /* number of octets of packet saved in file */
    unsigned int orig_len; /* actual length of packet */
} pcaprec_hdr_t;

/* packet data storage structure */
struct packet_data
{
    unsigned char payload[2048];  /* packet payload, including header */
    unsigned int payload_len;     /* payload length */
    struct packet_data *pkt_next; /* next packet */
};

/* flow data */
struct flow_data
{
    struct packet_data *packet_info; /* all packets' info of the flow */
};

/* key structure */
struct flow_key
{
    unsigned char sip[4];
    unsigned char dip[4];
    unsigned short sport;
    unsigned short dport;
    unsigned char proto;
    unsigned char padding[3];
};

/* hasflow_table key-value pair structure */
struct flow_entry
{
    struct flow_key five_tuple_key; /* hasflow_table key */
    struct flow_data flow_info;     /* packets' info */
    struct flow_entry *flow_next;   /* next key-value under the same bucket */
};

/* hasflow_table structure */
struct flow_table
{
    unsigned int size;           /* hasflow_table bucket size */
    struct flow_entry **buckets; /* pointers to key-value pair pointer */
};

void *my_malloc(size_t);

/* Following is the flow management api interface definition */
struct flow_table *flow_table_init(unsigned int); /* init a flow table */
struct flow_entry *flow_table_get_bucket(struct flow_table *, struct flow_key);
struct flow_entry *flow_table_flow_exist(struct flow_entry *, struct flow_key);
int flow_table_add_flow(struct flow_table *, struct flow_key);               /* add a flow to the flow table */
struct flow_data *flow_table_get_flow(struct flow_table *, struct flow_key); /* get a flow's data from the flow table */
void flow_table_del_flow(struct flow_table *, struct flow_key);              /* delete a flow from the flow table */

int flow_data_add_packet(struct flow_table *, struct flow_key, struct packet_data *); /* add a packet to the flow */
void flow_data_del_packets(struct flow_table *, struct flow_key);                     /* del all packets of the flow */

void flow_table_clean_up(struct flow_table *); /* clean up all flows and packets from the flow table */

/* ioctl cmd definition*/
enum ops
{
    GET_FROM_USER = 10,
    SET_TO_USER = 11,
};

#endif
