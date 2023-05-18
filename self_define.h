#ifndef _SELF_DEFINE_H_
#define _SELF_DEFINE_H_

#define DEV_NAME "simple_dev"
#define MAP_SIZE 10

// packet data
struct packet_data
{
    unsigned char payload[2048];
    struct packet_data *next;
};

// flow data
struct flow_data
{
    unsigned char data[16];
    struct packet_data *next;
};

// flow management key value pair
struct kv
{
    unsigned char key[16];
    struct flow_data *val;
    struct kv *next;
};

// hmap
struct hmap
{
    unsigned int size;
    struct kv **map;
};

// flow management map api interface
struct hmap *map_init(unsigned int);
int set_map(struct hmap *, char *, struct flow_data *);
struct flow_data *get_map(struct hmap *, char *);
void del_map(struct hmap *, char *);
void clean_up(struct hmap *);

enum ops
{
    GET_FROM_USER = 10,
    SET_TO_USER = 11,
};

#endif
