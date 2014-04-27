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
#include <linux/ktime.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/errno.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h> /* copy_from/to_user */
#include <asm/byteorder.h>

#define MSS 1460
#define MIN_RWND 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Kernel module to modify TCP receive window");

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;


//Function: modify TCP receive window
static unsigned int tcp_modify_outgoing(struct sk_buff *skb, unsigned short win)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	int tcplen=0;                    //Length of TCP
	
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
	}
	
	ip_header=(struct iphdr *)skb_network_header(skb);
	tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
	
	//Modify TCP window
	tcp_header->window=htons(win*MSS);

	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
			
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
											tcplen, ip_header->protocol,
											csum_partial((char *)tcp_header, tcplen, 0));
								  									 
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	return 1;
}

//POSTROUTING for outgoing packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned short int dst_port;     	  //TCP destination port
	
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
		//src_port=htons((unsigned short int) tcp_header->source);
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(dst_port==5001)
		{
			tcp_modify_outgoing(skb,MIN_RWND);
		}			
	}
	return NF_ACCEPT;
}


//Called when module loaded using 'insmod'
int init_module()
{
	//POSTROUTING
	nfho_outgoing.hook = hook_func_out;                 //function to call when conditions below met
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;       //called in post_routing
	nfho_outgoing.pf = PF_INET;                         //IPV4 packets
	nfho_outgoing.priority = NF_IP_PRI_FIRST;           //set to highest priority over all other hook functions
	nf_register_hook(&nfho_outgoing);                   //register hook*/
    
	printk(KERN_INFO "Start ICTCP kernel module\n");

	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	//Unregister the hook
	nf_unregister_hook(&nfho_outgoing);  
	printk(KERN_INFO "Stop ICTCP kernel module\n");
}
