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

#define MACADDRESS(addr) \
    ((unsigned char *)addr)[0], \
    ((unsigned char *)addr)[1], \
    ((unsigned char *)addr)[2], \
    ((unsigned char *)addr)[3], \
    ((unsigned char *)addr)[4], \
    ((unsigned char *)addr)[5]

#define H_PROTO(addr) \
    ((unsigned char *)addr)[0], \
    ((unsigned char *)addr)[1]
    

//#define IPADDRESS(addr) \
//	((unsigned char *)&addr)[3], \
//	((unsigned char *)&addr)[2], \
//	((unsigned char *)&addr)[1], \
//	((unsigned char *)&addr)[0]

#define IPADDRESS(addr) \
	((unsigned char *)addr)[3], \
	((unsigned char *)addr)[2], \
	((unsigned char *)addr)[1], \
	((unsigned char *)addr)[0]

static struct nf_hook_ops *http_sniffer_ops = NULL;

// static unsigned int is_ipv4(struct ethhdr *ethh){
//     if(ntohs(ethh->h_proto) == ETH_P_IP){
//         return 1;
//     }
//     return 0;
// }
// 
// static unsigned int is_tcp(struct iphdr *iph){
//     if(iph->protocol == IPPROTO_TCP){
//         return 1;
//     }
//     return 0;
// }

static unsigned int http_sniffer(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    // struct ethhdr *eth_h;
    struct iphdr *ipv4_hs;
    // struct tcphdr *tcp_h;
    unsigned char *eth_h;
    unsigned char *ipv4_h;
    unsigned char *tcp_h;
    __be16 hproto;
    __u8 ipproto;
    __be32 saddr;
    __be32 daddr;
    u32 sip;
    u32 dip;
    unsigned char *http_port = "\x00\x50";
    unsigned short *tcp_sp;
    eth_h = skb_mac_header(skb);
    printk(KERN_INFO "%ld", skb->len - skb->data_len);
    if((unsigned char *)skb->tail - eth_h > 14){
        hproto = *(eth_h + 12);
        printk(KERN_INFO "mac header to tail : %d", skb->tail - (sk_buff_data_t)eth_h);
        printk(KERN_INFO "========== packet ETH header ==========");
        printk(KERN_INFO "SRC MAC ADDR -> %02x:%02x:%02x:%02x:%02x:%02x", MACADDRESS(eth_h+6));
        printk(KERN_INFO "DES MAC ADDR -> %02x:%02x:%02x:%02x:%02x:%02x", MACADDRESS(eth_h));
        printk(KERN_INFO "H_PROTO -> %x", ntohs(hproto));
        printk(KERN_INFO "===================================");
        if(ntohs(hproto) == ETH_P_IP){
            ipv4_h = skb_network_header(skb);
            if((unsigned char *)skb->tail - ipv4_h > 20){
                ipv4_hs = ip_hdr(skb);
                ipproto = *(ipv4_h + 9);
                saddr = *(ipv4_h+12);
                daddr = *(ipv4_h+16);
                sip = ntohl(*(ipv4_h+12));
                dip = ntohl(*(ipv4_h+16));
                sip = ntohl(ipv4_hs->saddr);
                dip = ntohl(ipv4_hs->daddr);
                printk(KERN_INFO "ipv4 header to tail : %d", (unsigned char *)skb->tail - ipv4_h);
                printk(KERN_INFO "========== packet IP header ==========");
                //printk(KERN_INFO "SRC MAC ADDR -> %u.%u.%u.%u", IPADDRESS(sip));
                //printk(KERN_INFO "DES MAC ADDR -> %u.%u.%u.%u", IPADDRESS(dip));
                //printk(KERN_INFO "SRC MAC ADDR -> %u.%u.%u.%u", IPADDRESS(ipv4_h+12));
                //printk(KERN_INFO "DES MAC ADDR -> %u.%u.%u.%u", IPADDRESS(ipv4_h+16));
                printk(KERN_INFO "SRC MAC ADDR -> %pI4", ipv4_h+12);
                printk(KERN_INFO "DES MAC ADDR -> %pI4", ipv4_h+16);
                printk(KERN_INFO "IPPROTO -> %x", ipproto);
                printk(KERN_INFO "==================================");
                if(ipproto == IPPROTO_TCP){
                    tcp_h = skb_transport_header(skb);
                    tcp_sp = ntohs((unsigned short *)tcp_h);
                    if((unsigned char *)skb->tail - tcp_h > 20){
                        printk("%hu", *tcp_sp);
                        if(*tcp_sp == 80){
                            printk(KERN_INFO "It's http protocol");
                        }
                        //printk(KERN_INFO "transport header to tail : %d", (unsigned char *)skb->tail - tcp_h);
                        printk(KERN_INFO "========== packet TCP header ==========");
                        printk(KERN_INFO "tcp options data 5 bytes : %u %u %u %u %u", *(tcp_h+20), *(tcp_h+21), *(tcp_h+22), *(tcp_h+23), *(tcp_h+24));
                        printk(KERN_INFO "===================================");
                    }
                }
            }
        }
    }
    return NF_ACCEPT;
}
static int __init packet_sniffer_init(void) {
	http_sniffer_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (http_sniffer_ops != NULL) {
		http_sniffer_ops->hook = (nf_hookfn*)http_sniffer;                           
		http_sniffer_ops->hooknum = NF_INET_FORWARD;                                        
		http_sniffer_ops->pf = NFPROTO_IPV4;
		http_sniffer_ops->priority = NF_IP_PRI_FIRST;
		nf_register_net_hook(&init_net, http_sniffer_ops);
        printk(KERN_INFO "Init");
	}
	return 0;
}

static void __exit packet_sniffer_exit(void) {
	if (http_sniffer_ops  != NULL) {
		nf_unregister_net_hook(&init_net, http_sniffer_ops);
		kfree(http_sniffer_ops);
	}
	printk(KERN_INFO "Exit");
}

module_init(packet_sniffer_init);
module_exit(packet_sniffer_exit);

MODULE_LICENSE("GPL");
