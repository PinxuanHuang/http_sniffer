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

#define MACADDRESS(addr)            \
    ((unsigned char *)addr)[0],     \
        ((unsigned char *)addr)[1], \
        ((unsigned char *)addr)[2], \
        ((unsigned char *)addr)[3], \
        ((unsigned char *)addr)[4], \
        ((unsigned char *)addr)[5]

#define H_PROTO(addr)           \
    ((unsigned char *)addr)[0], \
        ((unsigned char *)addr)[1]

#define IPADDRESS(addr)             \
    ((unsigned char *)addr)[3],     \
        ((unsigned char *)addr)[2], \
        ((unsigned char *)addr)[1], \
        ((unsigned char *)addr)[0]

static struct nf_hook_ops *http_sniffer_ops = NULL;

static unsigned int http_sniffer(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    unsigned char *eth_h;
    unsigned char *ipv4_h;
    unsigned char *tcp_h;
    unsigned char *pkt_tail;
    unsigned short http_port = 80;
    unsigned short *tcp_sp;
    unsigned short *tcp_dp;
    unsigned char *data_offset;
    unsigned char *payload;
    __be16 hproto;
    __u8 ipproto;
    unsigned int payload_len;

    pkt_tail = skb_tail_pointer(skb);
    eth_h = skb_mac_header(skb);
    if (pkt_tail - eth_h > 14)
    {
        hproto = *(eth_h + 12);
        // printk(KERN_INFO "mac header to tail : %ld", pkt_tail - eth_h);
        printk(KERN_INFO "========== packet ETH header ==========");
        printk(KERN_INFO "SRC MAC ADDR -> %02x:%02x:%02x:%02x:%02x:%02x", MACADDRESS(eth_h + 6));
        printk(KERN_INFO "DES MAC ADDR -> %02x:%02x:%02x:%02x:%02x:%02x", MACADDRESS(eth_h));
        // printk(KERN_INFO "H_PROTO -> %x", ntohs(hproto));
        printk(KERN_INFO "===================================");
        if (ntohs(hproto) == ETH_P_IP)
        {
            ipv4_h = skb_network_header(skb);
            if (pkt_tail - ipv4_h > 20)
            {
                ipproto = *(ipv4_h + 9);
                // printk(KERN_INFO "ipv4 header to tail : %ld", pkt_tail - ipv4_h);
                printk(KERN_INFO "========== packet IP header ==========");
                printk(KERN_INFO "SRC MAC ADDR -> %pI4", ipv4_h + 12);
                printk(KERN_INFO "DES MAC ADDR -> %pI4", ipv4_h + 16);
                // printk(KERN_INFO "IPPROTO -> %x", ipproto);
                printk(KERN_INFO "==================================");
                if (ipproto == IPPROTO_TCP)
                {
                    tcp_h = skb_transport_header(skb);
                    tcp_sp = (unsigned short *)tcp_h;
                    tcp_dp = (unsigned short *)(tcp_h + 2);
                    if (pkt_tail - tcp_h > 20)
                    {
                        data_offset = (tcp_h + 12);
                        printk(KERN_INFO "========== packet TCP header ==========");
                        printk("tail to tcp header -> %ld", pkt_tail - tcp_h);
                        printk("SRC PORT %hu", ntohs(*tcp_sp));
                        printk("DST PORT %hu", ntohs(*tcp_dp));
                        printk("offset = %u", (*data_offset) >> 4);
                        printk(KERN_INFO "===================================");
                        payload = tcp_h + ((*data_offset) >> 4) * 4; // get the tcp packet payload
                        if (ntohs(*tcp_sp) == http_port || ntohs(*tcp_dp) == http_port)
                        {
                            int i;
                            printk(KERN_INFO "====== HTTP context =======");
                            payload_len = pkt_tail - payload;
                            printk(KERN_INFO "payload size = %d", payload_len);
                            for (i = 0; i < payload_len; i += 5)
                            {
                                if (i > 20)
                                    break;
                                printk(KERN_INFO "%c %c %c %c %c", *(payload + i), *(payload + i + 1), *(payload + i + 2), *(payload + i + 3), *(payload + i + 4));
                            }
                            printk(KERN_INFO "===========================");
                        }
                    }
                }
            }
        }
    }
    return NF_ACCEPT;
}
static int __init packet_sniffer_init(void)
{
    http_sniffer_ops = (struct nf_hook_ops *)kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (http_sniffer_ops != NULL)
    {
        http_sniffer_ops->hook = (nf_hookfn *)http_sniffer;
        http_sniffer_ops->hooknum = NF_INET_FORWARD;
        http_sniffer_ops->pf = NFPROTO_IPV4;
        http_sniffer_ops->priority = NF_IP_PRI_FIRST;
        nf_register_net_hook(&init_net, http_sniffer_ops);
        printk(KERN_INFO "Init");
    }
    return 0;
}

static void __exit packet_sniffer_exit(void)
{
    if (http_sniffer_ops != NULL)
    {
        nf_unregister_net_hook(&init_net, http_sniffer_ops);
        kfree(http_sniffer_ops);
    }
    printk(KERN_INFO "Exit");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);

MODULE_LICENSE("GPL");
