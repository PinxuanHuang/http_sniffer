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

static int mem_counter = 0;

void *my_malloc(size_t size)
{
    void *result;

#ifdef __KERNEL__
    result = kmalloc(size, GFP_ATOMIC); // GFP_KERNEL, GFP_ATOMIC
#else                                   /* user space */
    result = malloc(size);
#endif
    mem_counter += 1;
    return result;
}

void my_free(void *ptr)
{
#ifdef __KERNEL__
    kfree(ptr);
#else /* user space */
    free(ptr);
#endif
    mem_counter -= 1;
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
int flow_table_add_flow(struct flow_table *table, struct flow_key key)
{
    struct flow_entry *bucket;
    struct flow_entry *new_flow;

    /* get the bucket */
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
    // if(!sequential_lock)
    // {
    //     printk(KERN_INFO "");
    // }
    printk(KERN_INFO "Start add a packet");
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
        printk(KERN_INFO "[Init] End add a packet");
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
        pkt_data = pkt_data->pkt_next;
    }
    printk(KERN_INFO "[Append] End add a packet");
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
    unsigned int packet_clean_up_counter = 0;
    struct flow_entry *bucket_head;
    struct flow_data flow_head;
    struct packet_data *pkt;

    printk(KERN_INFO "mem : %d", mem_counter);
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
                packet_clean_up_counter += 1;
            }
            table->buckets[i] = bucket_head->flow_next;
            // printf("clean up key : %s\n", bucket_head->five_tuple_key.sip);
            printk(KERN_INFO "clean up key : (sip:sport) %u.%u.%u.%u:%u | (dip:dport) %u.%u.%u.%u:%u\n",
                   bucket_head->five_tuple_key.sip[0],
                   bucket_head->five_tuple_key.sip[1],
                   bucket_head->five_tuple_key.sip[2],
                   bucket_head->five_tuple_key.sip[3],
                   bucket_head->five_tuple_key.sport,
                   bucket_head->five_tuple_key.dip[0],
                   bucket_head->five_tuple_key.dip[1],
                   bucket_head->five_tuple_key.dip[2],
                   bucket_head->five_tuple_key.dip[3],
                   bucket_head->five_tuple_key.dport);
            my_free(bucket_head);
        }
    }
    printk(KERN_INFO "Total clean up %d packets\n", packet_clean_up_counter);
    // printf("clean up buckets\n");
    my_free(table->buckets);
    // printf("clean up table\n");
    my_free(table);
    printk(KERN_INFO "mem : %d", mem_counter);
    return;
}

/* Export these function */
EXPORT_SYMBOL(flow_table_init);
EXPORT_SYMBOL(flow_table_get_bucket);
EXPORT_SYMBOL(flow_table_flow_exist);
EXPORT_SYMBOL(flow_table_add_flow);
EXPORT_SYMBOL(flow_table_get_flow);
EXPORT_SYMBOL(flow_table_del_flow);
EXPORT_SYMBOL(flow_data_add_packet);
EXPORT_SYMBOL(flow_data_del_packets);
EXPORT_SYMBOL(flow_table_clean_up);

// static int __init hashmap_init(void)
// {
//     printk(KERN_INFO "[*] INIT HASHMAP MODULE");
//     return 0;
// }

// static void __exit hashmap_exit(void)
// {
//     printk(KERN_INFO "[*] EXIT HASHMAP MODULE");
//     return;
// }

// module_init(hashmap_init);
// module_exit(hashmap_exit);

MODULE_LICENSE("GPL");