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

static struct nf_hook_ops *http_sniffer_ops = NULL;

static unsigned int is_ip(){

    return 0;
}

static unsigned int http_sniffer(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
    struct ethhdr *eth_hdr;
    eth_hdr = (struct ethhdr*)skb_mac_header(skb);
    // printk(KERN_INFO "This is %x proto", ntohs(eth_hdr->h_proto));
    // if(ntohs(eth_hdr->h_proto) == ETH_P_IP){
    //    printk(KERN_INFO "It's an ipv4 addr");
    // }
    // else {
    //     printk(KERN_INFO "I'm not an IPv4 hdr");
    // }
    if(ntohs(eth_hdr->h_proto) == ETH_P_IP){
         unsigned char *net_proto = skb_network_header(skb)+9;
         printk(KERN_INFO "This is %x\n proto", *net_proto);
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
