#include "self_define.h"

#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

void *my_malloc(size_t size)
{
    void *result;

#ifdef __KERNEL__
    result = kmalloc(size, GFP_KERNEL); // GFP_KERNEL, GFP_ATOMIC
#else                                   /* user space */
    result = malloc(size);
#endif

    return result;
}

void my_free(void *ptr)
{
#ifdef __KERNEL__
    kfree(ptr);
#else /* user space */
    free(ptr);
#endif
}

/* Initialize the hmap */
struct hmap *map_init(unsigned int size)
{
    // [struct flow_key *, ..., ...]
    struct hmap *map = my_malloc(sizeof(struct hmap));
    map->size = size;
    map->map = my_malloc(sizeof(struct key_value *) * size);
    memset(map->map, 0, sizeof(struct key_value *) * size);
    return map;
}

/* set a key:val in the hmap */
int set_map(struct hmap *map, struct flow_key key, struct packet_data *value)
{
    int exist = 0;
    struct key_value *flow_key = map->map[(key.dport) % (map->size)]; /* specific flow key */
    struct key_value *kv_head = flow_key;
    struct packet_data *packet_data_head;
    struct packet_data *packet_data_next;

    /* if the bucket doesn't have any flow */
    if (flow_key == NULL)
    {
        struct key_value *new_flow = my_malloc(sizeof(struct key_value));
        new_flow->key = key;
        new_flow->value.head = value;
        new_flow->next = NULL;
        map->map[(key.dport) % (map->size)] = new_flow;
        return 0;
    }

    /* check whether the key has already exised or not */
    while (flow_key)
    {
        if (memcmp(&(flow_key->key), &key, 16) == 0)
        {
            exist = 1;
            break;
        }
        flow_key = flow_key->next;
    }

    /* if key has alreadt existed, update its value */
    if (exist)
    {
        packet_data_head = flow_key->value.head;
        packet_data_next = packet_data_head->next;
        while (packet_data_next)
        {
            packet_data_head = packet_data_head->next;
            packet_data_next = packet_data_next->next;
        }
        packet_data_head->next = value;
    }

    /* else set a new flow_key and update the bucket head */
    else
    {
        struct key_value *new_flow = my_malloc(sizeof(struct key_value));
        new_flow->key = key;
        new_flow->value.head = value;
        new_flow->next = kv_head;
        map->map[(key.dport) % (map->size)] = new_flow;
    }
    return 0;
}

/* Get a value of the specific key */
struct flow_data get_map(struct hmap *map, struct flow_key key)
{
    struct key_value *flow_key = map->map[(key.dport) % (map->size)];
    struct flow_data value = {NULL}; /* ??? */

    // if the bucket doesn't have any flow
    while (flow_key)
    {
        if (memcmp(&(flow_key->key), &key, 16) == 0)
        {
            printf("key : %s match key: %s\n", flow_key->key.sip, key.sip);
            value = flow_key->value;
            break;
        }
        flow_key = flow_key->next;
    }

    return value;
}

/* Delete a key from hmap */
void del_map(struct hmap *map, struct flow_key key)
{
    struct key_value *kv_head = map->map[(key.dport) % (map->size)];
    struct key_value *kv_prev;
    struct packet_data *pkt_head;
    struct packet_data *pkt_prev;

    if (memcmp(&(kv_head->key), &key, 16) == 0)
    {
        map->map[(key.dport) % (map->size)] = kv_head->next;
        pkt_head = kv_head->value.head;
        while (pkt_head)
        {
            pkt_prev = pkt_head;
            pkt_head = pkt_head->next;
            printf("del key : %s | data: %s\n", kv_head->key.sip, pkt_prev->payload);
            my_free(pkt_prev);
        }
        printf("del up key : %s\n", kv_head->key.sip);
        my_free(kv_head);
        return;
    }

    while (kv_head)
    {
        if (memcmp(&(kv_head->key), &key, 16) == 0)
        {
            pkt_head = kv_head->value.head;
            while (pkt_head)
            {
                pkt_prev = pkt_head;
                pkt_head = pkt_head->next;
                printf("del key : %s | data: %s\n", kv_head->key.sip, pkt_prev->payload);
                my_free(pkt_prev);
            }
            kv_prev->next = kv_head->next;
            printf("del key : %s\n", kv_head->key.sip);
            my_free(kv_head);
            break;
        }
        kv_prev = kv_head;
        kv_head = kv_head->next;
    }
    return;
}

/* Clean up the hmap */
void clean_up(struct hmap *map)
{
    int i;
    struct key_value *kv_head;
    struct key_value *kv_prev;
    struct packet_data *pkt_head;
    struct packet_data *pkt_prev;

    for (i = 0; i < map->size; i++)
    {
        kv_head = map->map[i];
        while (kv_head)
        {
            pkt_head = kv_head->value.head;
            while (pkt_head)
            {
                pkt_prev = pkt_head;
                pkt_head = pkt_head->next;
                printf("clean up key : %s | data: %s\n", kv_head->key.sip, pkt_prev->payload);
                my_free(pkt_prev);
            }
            kv_prev = kv_head;
            kv_head = kv_head->next;
            printf("clean up key : %s\n", kv_prev->key.sip);
            my_free(kv_prev);
        }
    }
    printf("clean up buckets\n");
    my_free(map->map);
    printf("clean up map\n");
    my_free(map);
    return;
}

int main(void)
{
    printf("=== Start map testing ===\n");
    struct hmap *map = map_init(MAP_SIZE);

    /* testing payload */
    struct flow_data payload1 = {NULL};
    struct flow_data payload2 = {NULL};
    struct packet_data *head;

    /* testing payload data */
    char test_data1[10] = "hello";
    char test_data2[10] = "world";
    char test_data3[10] = "oops";
    char test_data4[10] = "ohya";
    char test_data5[10] = "data5";
    char test_data6[10] = "data6";

    /* testing key */
    struct flow_key key1 = {{'1', '1', '1', '\0'}, {'1', '1', '1', '1'}, 80, 80, 'a', {'1', '1', '1'}};
    struct flow_key key2 = {{'2', '2', '2', '\0'}, {'2', '2', '2', '2'}, 90, 90, 'b', {'2', '2', '2'}};
    struct flow_key key3 = {{'3', '3', '3', '\0'}, {'3', '3', '3', '3'}, 100, 100, 'c', {'3', '3', '3'}};
    struct flow_key key4 = {{'4', '4', '4', '\0'}, {'4', '4', '4', '4'}, 110, 110, 'd', {'4', '4', '4'}};

    /* testing packet data */
    struct packet_data *data1 = my_malloc(sizeof(struct packet_data));
    struct packet_data *data2 = my_malloc(sizeof(struct packet_data));
    struct packet_data *data3 = my_malloc(sizeof(struct packet_data));
    struct packet_data *data4 = my_malloc(sizeof(struct packet_data));
    struct packet_data *data5 = my_malloc(sizeof(struct packet_data));
    struct packet_data *data6 = my_malloc(sizeof(struct packet_data));

    memcpy(data1->payload, test_data1, 10);
    data1->next = NULL;
    memcpy(data2->payload, test_data2, 10);
    data2->next = NULL;
    memcpy(data3->payload, test_data3, 10);
    data3->next = NULL;
    memcpy(data4->payload, test_data4, 10);
    data4->next = NULL;
    memcpy(data5->payload, test_data5, 10);
    data5->next = NULL;
    memcpy(data6->payload, test_data6, 10);
    data6->next = NULL;

    /* set testing */
    set_map(map, key1, data1);
    set_map(map, key1, data2);
    set_map(map, key2, data3);
    set_map(map, key2, data4);
    set_map(map, key3, data6);
    set_map(map, key3, data5);

    /* get testing */
    payload1 = get_map(map, key2);
    payload2 = get_map(map, key4);

    if (payload1.head)
    {
        head = payload1.head;
        while (head)
        {
            printf("get key2 data : %s\n", head->payload);
            head = head->next;
        }
        head = NULL;
    }
    else
    {
        printf("There's no data with key2\n");
    }

    if (payload2.head)
    {
        head = payload2.head;
        while (head)
        {
            printf("get key4 data : %s\n", head->payload);
            head = head->next;
        }
    }
    else
    {
        printf("There's no data with key4\n");
    }

    /* del testing */
    del_map(map, key1);
    del_map(map, key2);

    /* set testing */
    clean_up(map);

    printf("=== End map testing ===\n");
    return 0;
}