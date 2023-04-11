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

#define IPADDRESS(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]

static struct nf_hook_ops *http_sniffer_ops = NULL;

static unsigned int is_ipv4(struct ethhdr *ethh){
    if(ntohs(ethh->h_proto) == ETH_P_IP){
        return 1;
    }
    return 0;
}

static unsigned int is_tcp(struct iphdr *iph){
    if(iph->protocol == IPPROTO_TCP){
        return 1;
    }
    return 0;
}

static unsigned int http_sniffer(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    struct ethhdr *ethh;
    ethh = eth_hdr(skb);
    if(is_ipv4(ethh)){
        struct iphdr *iph;
        __u32 sip;
        __u32 dip;
        iph = ip_hdr(skb);
        sip = ntohl(iph->saddr);
        dip = ntohl(iph->daddr);
        if(is_tcp(iph)){
            printk(KERN_INFO "saddr:%u.%u.%u.%u daddr:%u.%u.%u.%u is tcp", IPADDRESS(sip), IPADDRESS(dip));
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