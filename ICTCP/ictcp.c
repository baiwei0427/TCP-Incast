#include <linux/module.h> 
#include <linux/kernel.h> 
#include <linux/init.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/checksum.h>
#include <linux/netfilter_ipv4.h>
#include <linux/string.h>
#include <linux/time.h>  
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h> /* copy_from/to_user */
#include <asm/byteorder.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei wbaiab@ust.hk");
MODULE_VERSION("Beta");
MODULE_DESCRIPTION("Kernel module in Linux for ICTCP");

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;

//POSTROUTING for outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;         //IP  header struct
    struct tcphdr *tcp_header;       //TCP header struct
	unsigned short int src_port;     //TCP source port
	int tcplen=0;                    //Length of TCP
	
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
    if (!ip_header)
    {
		return NF_ACCEPT;
    }

	if(ip_header->protocol==IPPROTO_TCP) //TCP
	{
		 tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
         //Get source and destination TCP port
         src_port=htons((unsigned short int) tcp_header->source);
		 //We only deal with iperf traffic whose server port is 5001
		 if(src_port==5001&&tcp_header->ack)
		 {
			if (skb_linearize(skb)!= 0) 
			{
				return NF_ACCEPT;
			}
			ip_header=(struct iphdr *)skb_network_header(skb);
			tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
			//1MSS=12*128
			tcp_header->window=htons(1500);

			//TCP length=IP total length - IP header length
			tcplen=ntohs(ip_header->tot_len)-(ip_header->ihl<<2);
			tcp_header->check=0;

			//static inline __sum16 tcp_v4_check(int len, __be32 saddr,__be32 daddr, __wsum base)
			tcp_header->check = tcp_v4_check(tcplen,
											 ip_header->saddr,
											 ip_header->daddr,
											 csum_partial((char *)tcp_header,tcplen,0));
			
		 }
	}

	return NF_ACCEPT;
}

//Called when module loaded using 'insmod'
int init_module()
{
	//POSTROUTING
	nfho_outgoing.hook = hook_func_out;                   //function to call when conditions below met
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;         //called in post_routing
	nfho_outgoing.pf = PF_INET;                           //IPV4 packets
	nfho_outgoing.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_hook(&nfho_outgoing);                     //register hook*/
        
    printk(KERN_INFO "Start ICTCP kernel module\n");

    return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	nf_unregister_hook(&nfho_outgoing);  
    printk(KERN_INFO "Stop ICTCP kernel module\n");

}