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
    unsigned char payload[2048]; /* packet payload, including header */
    struct packet_data *next;    /* next packet */
};

/* flow data */
struct flow_data
{
    struct packet_data *head;
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

/* hashmap key-value pair structure */
struct key_value
{
    struct flow_key key; /* hashmap key */
    struct flow_data value;
    struct key_value *next; /* next key-value under the same bucket */
};

/* hashmap structure */
struct hmap
{
    unsigned int size;      /* hashmap bucket size */
    struct key_value **map; /* pointers to key-value pair pointer */
};

/* flow management map api interface */
struct hmap *map_init(unsigned int);
int set_map(struct hmap *, struct flow_key, struct packet_data *);
struct flow_data get_map(struct hmap *, struct flow_key);
void del_map(struct hmap *, struct flow_key);
void clean_up(struct hmap *);

/* ioctl cmd definition*/
enum ops
{
    GET_FROM_USER = 10,
    SET_TO_USER = 11,
};

#endif
