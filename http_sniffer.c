#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include "self_define.h"

static unsigned short HTTP_PORT = 80;
static struct nf_hook_ops *http_sniffer_ops = NULL;
static struct flow_table *table;

static int file_open(struct inode *i, struct file *f)
{
    // open the character file resource ops
    printk(KERN_INFO "[*] open dev file");
    return 0;
}

static long my_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int i;
    unsigned int res;
    struct flow_entry *flow = NULL;
    struct packet_data *pkt_data = NULL;

    /* get the first packet from the buckets */
    for (i = 0; i < table->size; i++)
    {
        flow = table->buckets[i];
        if (flow)
        {
            pkt_data = flow->flow_info.packet_info;
            break;
        }
    }

    printk(KERN_INFO "[*] ioctl comm...");
    switch (cmd)
    {
    case GET_FROM_USER:
        printk(KERN_INFO "[*] Nothing to do with the data pass from user space...");
        break;
    case SET_TO_USER:
        printk(KERN_INFO "[*] Pass sip and dip to user space ft_info...");
        if (pkt_data)
        {
            res = copy_to_user((struct packet_data *)arg, pkt_data, sizeof(struct packet_data));
            if (res)
            {
                printk(KERN_ERR "Err when copy to user!!!");
            }
            printk(KERN_INFO "copy to user~~~");
        }
        else
        {
            printk(KERN_INFO "There's no any data need to copy to user~~~");
        }
        break;
    default:
        printk(KERN_INFO "[*] Default");
    }

    return 0;
}

static int file_close(struct inode *i, struct file *f)
{
    // close the character file resource ops
    printk(KERN_INFO "[*] close dev file");
    return 0;
}

struct file_operations my_fops = {
    .open = file_open,
    .unlocked_ioctl = my_ioctl,
    .release = file_close,
};

struct miscdevice my_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEV_NAME,
    .fops = &my_fops,
    .mode = 0666,
};

static unsigned int http_sniffer(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    unsigned char *eth_h;
    unsigned char *ipv4_h;
    unsigned char *tcp_h;
    unsigned char *pkt_tail;
    unsigned short tcp_sp;
    unsigned short tcp_dp;
    __be16 hproto;
    __u8 ipproto;
    struct flow_key key = {0};
    struct packet_data *pkt_data = NULL;

    pkt_tail = skb_tail_pointer(skb);
    eth_h = skb_mac_header(skb);

    if (pkt_tail - eth_h < 14)
    {
        return NF_ACCEPT;
    }

    hproto = *(eth_h + 12);
    if (ntohs(hproto) != ETH_P_IP)
    {
        return NF_ACCEPT;
    }

    ipv4_h = skb_network_header(skb);
    if (pkt_tail - ipv4_h <= 20)
    {
        return NF_ACCEPT;
    }

    ipproto = *(ipv4_h + 9);
    if (ipproto != IPPROTO_TCP)
    {
        return NF_ACCEPT;
    }

    tcp_h = skb_transport_header(skb);
    if (pkt_tail - tcp_h < 20)
    {
        return NF_ACCEPT;
    }

    tcp_sp = ntohs(*(unsigned short *)tcp_h);
    tcp_dp = ntohs(*(unsigned short *)(tcp_h + 2));
    if (tcp_sp != HTTP_PORT && tcp_dp != HTTP_PORT)
    {
        return NF_ACCEPT;
    }

    // if the packet size greater than 54 bytes, except the packet header
    printk(KERN_INFO "[*] It's http packet | eth to tail size [%ld]", (pkt_tail - eth_h));
    if (pkt_tail - eth_h > 54)
    {
        /*
        specific the flow
        set larger port and ip to sip and sport
        set lower port and ip to dip and dport
        finally, set proto
        */
        if (tcp_sp > tcp_dp)
        {
            memcpy(&(key.sip), ipv4_h + 12, 4);
            memcpy(&(key.sport), &tcp_sp, 2);
            memcpy(&(key.dip), ipv4_h + 16, 4);
            memcpy(&(key.dport), &tcp_dp, 2);
        }
        else
        {
            memcpy(&(key.sip), ipv4_h + 16, 4);
            memcpy(&(key.sport), &tcp_dp, 2);
            memcpy(&(key.dip), ipv4_h + 12, 4);
            memcpy(&(key.dport), &tcp_sp, 2);
        }
        memcpy(&(key.proto), ipv4_h + 9, 1);

        /* Initialize the packet data structure and assign the payload data */
        // pkt_data = kcalloc(1, sizeof(struct packet_data), GFP_ATOMIC);
        pkt_data = my_malloc(sizeof(struct packet_data));
        memcpy(pkt_data->payload, eth_h, (pkt_tail - eth_h));
        pkt_data->payload_len = pkt_tail - eth_h;
        pkt_data->pkt_next = NULL;

        /* set the packet data to the flow */
        flow_data_add_packet(table, key, pkt_data);
        printk(KERN_INFO "[sniff] flow : (sip:sport) %u.%u.%u.%u:%u | (dip:dport) %u.%u.%u.%u:%u\n",
               key.sip[0],
               key.sip[1],
               key.sip[2],
               key.sip[3],
               key.sport,
               key.dip[0],
               key.dip[1],
               key.dip[2],
               key.dip[3],
               key.dport);
    }

    // TODO design the flow management struct to record packets payload

    return NF_ACCEPT;
}

/*
 * Define functions needs in init progress
 */
static int hook_reg(void)
{
    http_sniffer_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (http_sniffer_ops != NULL)
    {
        http_sniffer_ops->hook = (nf_hookfn *)http_sniffer;
        http_sniffer_ops->hooknum = NF_INET_FORWARD;
        http_sniffer_ops->pf = NFPROTO_IPV4;
        http_sniffer_ops->priority = NF_IP_PRI_FIRST;
        if (nf_register_net_hook(&init_net, http_sniffer_ops) < 0)
        {
            return -ENODEV;
        }
        printk(KERN_INFO "=== Init ===");
    }
    else
    {
        return -ENODEV;
    }
    return 0;
}

/*
 * Define functions need in exit progress
 */
static void hook_unreg(void)
{
    if (http_sniffer_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, http_sniffer_ops);
        kfree(http_sniffer_ops);
    }
    printk(KERN_INFO "=== Exit ===");
}

static int __init packet_sniffer_init(void)
{
    int fail = 0;
    printk(KERN_INFO "=== MODULE INIT ===");
    // register hook
    fail = hook_reg();
    if (fail)
    {
        goto HOOK_REG_FAIL;
    }

    // register device
    fail = misc_register(&my_dev);
    if (fail)
    {
        goto DEV_REG_FAIL;
    }

    // initialize flow_table
    table = flow_table_init(MAP_SIZE);
    // assign ioctl data
    // ft_info = kcalloc(1,  sizeof(struct ft), GFP_KERNEL);
    // if(ft_info == NULL){
    //     goto IOCTL_ASSIGN_FAIL;
    // }

    return 0;

// IOCTL_ASSIGN_FAIL:
//     misc_deregister(&my_dev);
DEV_REG_FAIL:
    nf_unregister_net_hook(&init_net, http_sniffer_ops);
    kfree(http_sniffer_ops);

HOOK_REG_FAIL:
    return -ENODEV;
}

static void __exit packet_sniffer_exit(void)
{
    // unregister hook
    hook_unreg();

    // unregister device
    misc_deregister(&my_dev);

    // release flow_table
    flow_table_clean_up(table);

    // release ioctl data
    // kfree(ft_info);
    printk(KERN_INFO "=== MODULE EXIT ===");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);

MODULE_LICENSE("GPL");
