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

/* init the flow table*/
struct flow_table *flow_table_init(unsigned int size)
{
    struct flow_table *flow_table = my_malloc(sizeof(struct flow_table));
    flow_table->size = size;
    flow_table->buckets = my_malloc(sizeof(struct flow_entry *) * size);
    memset(flow_table->buckets, 0, sizeof(struct flow_entry *) * size);
    return flow_table;
}

/* get the specific bucket where the key should be resided */
struct flow_entry *flow_table_get_bucket(struct flow_table *table, struct flow_key key)
{
    struct flow_entry *bucket;
    bucket = table->buckets[(key.sport + key.dport) % (table->size)];
    return bucket;
}

/* check whether the flow has already existed or not */
struct flow_entry *flow_table_flow_exist(struct flow_entry *bucket, struct flow_key key)
{
    while (bucket)
    {
        if (memcmp(&(bucket->five_tuple_key), &key, sizeof(struct flow_key)) == 0)
        {
            // printf("%s is already existed\n", key.sip);
            return bucket;
        }
        bucket = bucket->flow_next;
    }
    return NULL;
}

/* add a flow to flow table */
// int flow_table_add_flow(struct flow_entry *bucket, struct flow_key key)
int flow_table_add_flow(struct flow_table *table, struct flow_key key)
{
    // struct flow_entry **indirect;
    struct flow_entry *bucket;
    struct flow_entry *new_flow;

    /* get the bucket */
    // indirect = &bucket;
    bucket = flow_table_get_bucket(table, key);

    /* init a new flow */
    new_flow = my_malloc(sizeof(struct flow_entry));
    new_flow->five_tuple_key = key;
    new_flow->flow_info.packet_info = NULL;
    new_flow->flow_next = NULL;

    if (!bucket)
    {
        table->buckets[(key.sport + key.dport) % (table->size)] = new_flow;
        // printf("[No bucket in %d] Succ to add flow sip : %s\n", (key.sport + key.dport) % (table->size), key.sip);
    }
    else
    {
        while (bucket)
        {
            if (!(bucket->flow_next))
            {
                bucket->flow_next = new_flow;
                // printf("[bucket in %d] Succ to add flow sip : %s\n", (key.sport + key.dport) % (table->size), key.sip);
                break;
            }
            bucket = bucket->flow_next;
        }
    }
    // while (*indirect)
    // {
    //     indirect = &(*indirect)->flow_next;
    // }
    // *indirect = new_flow;
    return 0;
}

/* get the specific flow's data */
struct flow_data *flow_table_get_flow(struct flow_table *table, struct flow_key key)
{
    struct flow_entry *bucket, *current_flow;
    struct flow_data *data = NULL;

    bucket = flow_table_get_bucket(table, key);
    current_flow = flow_table_flow_exist(bucket, key);
    if (current_flow)
    {
        data = &(current_flow->flow_info);
    }
    return data;
}

/* TODO */
/* delete the specific flow from the flow table */
void flow_table_del_flow(struct flow_table *table, struct flow_key key)
{
    return;
}

/* add a packet to the specific flow */
int flow_data_add_packet(struct flow_table *table, struct flow_key key, struct packet_data *pkt)
{
    struct flow_entry *bucket;
    struct flow_entry *current_flow;
    struct flow_data *current_flow_data;
    struct packet_data *pkt_data;

    /* get the specific bucket and check whether the flow exist or not */
    bucket = flow_table_get_bucket(table, key);
    current_flow = flow_table_flow_exist(bucket, key);

    /* if the flow not exist, add it to the flow table */
    if (!current_flow)
    {
        flow_table_add_flow(table, key);
    }

    /* get the specific flow data */
    current_flow_data = flow_table_get_flow(table, key);
    pkt_data = current_flow_data->packet_info;

    /* if there's no any packet in the flow data*/
    if (!pkt_data)
    {
        current_flow_data->packet_info = pkt;
        return 0;
    }

    /* append the packet to the tail, meaning it's latest */
    while (pkt_data)
    {
        if (!(pkt_data->pkt_next))
        {
            pkt_data->pkt_next = pkt;
            break;
        }
    }
    return 0;
}

/* TODO */
/* del all packets of a flow */
void flow_data_del_packets(struct flow_table *table, struct flow_key key)
{
    return;
}

/* Clean up the flow_table */
void flow_table_clean_up(struct flow_table *table)
{
    int i;
    struct flow_entry *bucket_head;
    struct flow_data flow_head;
    struct packet_data *pkt;

    for (i = 0; i < table->size; i++)
    {
        while (table->buckets[i])
        {
            bucket_head = table->buckets[i];
            flow_head = bucket_head->flow_info;
            while (flow_head.packet_info)
            {
                pkt = flow_head.packet_info;
                flow_head.packet_info = pkt->pkt_next;
                // printf("clean up key : %s | data: %s\n", bucket_head->five_tuple_key.sip, pkt->payload);
                my_free(pkt);
            }
            table->buckets[i] = bucket_head->flow_next;
            // printf("clean up key : %s\n", bucket_head->five_tuple_key.sip);
            my_free(bucket_head);
        }
    }
    // printf("clean up buckets\n");
    my_free(table->buckets);
    // printf("clean up table\n");
    my_free(table);
    return;
}

int main(void)
{
    printf("=== Start map testing ===\n");
    struct flow_data *head;
    struct flow_entry *bucket;
    struct flow_table *table = flow_table_init(MAP_SIZE);

    /* testing payload data */
    char test_data1[10] = "hello";
    char test_data2[10] = "world";
    char test_data3[10] = "oops";
    char test_data4[10] = "ohya";
    char test_data5[10] = "data5";
    char test_data6[10] = "data6";

    // /* testing key */
    struct flow_key key1 = {{'1', '1', '1', '\0'}, {'1', '1', '1', '1'}, 80, 80, 'a', {'1', '1', '1'}};
    struct flow_key key2 = {{'2', '2', '2', '\0'}, {'2', '2', '2', '2'}, 91, 91, 'b', {'2', '2', '2'}};
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
    data1->payload_len = sizeof(test_data1);
    data1->pkt_next = NULL;
    memcpy(data2->payload, test_data2, 10);
    data2->payload_len = sizeof(test_data2);
    data2->pkt_next = NULL;
    memcpy(data3->payload, test_data3, 10);
    data3->payload_len = sizeof(test_data3);
    data3->pkt_next = NULL;
    memcpy(data4->payload, test_data4, 10);
    data4->payload_len = sizeof(test_data4);
    data4->pkt_next = NULL;
    memcpy(data5->payload, test_data5, 10);
    data5->payload_len = sizeof(test_data5);
    data5->pkt_next = NULL;
    memcpy(data6->payload, test_data6, 10);
    data6->payload_len = sizeof(test_data6);
    data6->pkt_next = NULL;

    /* set testing */
    flow_data_add_packet(table, key1, data1);
    flow_data_add_packet(table, key1, data2);
    flow_data_add_packet(table, key2, data3);
    flow_data_add_packet(table, key2, data4);
    flow_data_add_packet(table, key3, data5);
    flow_data_add_packet(table, key3, data6);

    /* get testing */

    /* del testing */
    flow_table_clean_up(table);

    printf("=== End map testing ===\n");
    return 0;
}