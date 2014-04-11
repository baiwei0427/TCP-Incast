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

#include "hash.h"

#define MSS 1460 //MSS: 1460 bytes
#define MIN_RTT 100	//Base RTT: 100 us
#define MIN_RWND 2	//Minimal Window: 2MSS for ICTCP

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Kernel module in Linux for ICTCP");

//Average RTT (microseconds)
static unsigned int avg_rtt;

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;

//Incoming packets PREROUTING
static struct nf_hook_ops nfho_incoming;

//Function to calculate microsecond-granularity TCP timestamp value
//Current TCP timestamp value is jiffies (4ms-granularity in our testbed)
static unsigned int get_tsval()
{
	//Get current time. Then transfer it from nanosecond to microsecond 
	//2^10=1024 
	//In theory, 32bit TCP timestamp value should be enough 
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

//POSTROUTING for outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;         //IP  header struct
	struct tcphdr *tcp_header;       //TCP header struct
	unsigned short int dst_port;     //TCP destination port
	unsigned char *tcp_opt=NULL;	 //TCP option
	unsigned int *tsval=NULL;	     //TCP timestamp option
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
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//We only use ICTCP to control incast traffic (dst port 5001)
		if(dst_port==5001)
		{
			if (skb_linearize(skb)!= 0) 
			{
				return NF_ACCEPT;
			}
			ip_header=(struct iphdr *)skb_network_header(skb);
			tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
			
			//TCP option offset=IP header pointer+IP header length+TCP header length
			tcp_opt=(unsigned char*)ip_header+ ip_header->ihl*4+20;
			
			if(tcp_header->syn)
			{
				//In SYN packets, TCP option=MSS(4)+SACK(2)+Timestamp(10)
				tcp_opt=tcp_opt+6;
			}
			else
			{
				//In ACK packets, TCP option=NOP(1)+NOP(1)+Timestamp(10)
				tcp_opt=tcp_opt+2;
			}
			
			//Option kind: Timestamp(8)
			if(*tcp_opt==8)
			{
				//Get pointer to Timestamp value (TSval)
				tsval=(unsigned int*)(tcp_opt+2);
				//Modify TCP Timestamp value
				*tsval=htonl(get_tsval());
			}
			
			//Modify TCP window
			tcp_header->window=htons(2920);

			//TCP length=Total length - IP header length
			tcplen=skb->len-(ip_header->ihl<<2);
			tcp_header->check=0;
			
			tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                  tcplen, ip_header->protocol,
                                  csum_partial((char *)tcp_header, tcplen, 0));
								  									 
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			
		 }
	}

	return NF_ACCEPT;
}

//PREROUTING for incoming packets
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;         //IP  header struct
	struct tcphdr *tcp_header;       //TCP header struct
	unsigned short int src_port;     //TCP source port
	unsigned char *tcp_opt=NULL;	 //TCP option
	unsigned int *tsecr=NULL;	     //TCP timestamp option
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
		//Get source TCP port
		src_port=htons((unsigned short int) tcp_header->source);
		
		//We only use ICTCP to control incast traffic (incoming packets with src port 5001)
		if(src_port==5001)
		{
			if (skb_linearize(skb)!= 0) 
			{
				return NF_ACCEPT;
			}
			ip_header=(struct iphdr *)skb_network_header(skb);
			tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
			
			//TCP option offset=IP header pointer+IP header length+TCP header length
			tcp_opt=(unsigned char*)ip_header+ ip_header->ihl*4+20;
			
			if(tcp_header->syn)
			{
				//In SYN packets, TCP option=MSS(4)+SACK(2)+Timestamp(10)
				tcp_opt=tcp_opt+6;
			}
			else
			{
				//In ACK packets, TCP option=NOP(1)+NOP(1)+Timestamp(10)
				tcp_opt=tcp_opt+2;
			}
			
			//Option kind: Timestamp(8)
			if(*tcp_opt==8)
			{
				//Get pointer to Timestamp echo reply (TSecr)
				tsecr=(unsigned int*)(tcp_opt+6);
				
				//Calculate one RTT sample
				printk(KERN_INFO "RTT sample: %u\n",get_tsval()-ntohl(*tsecr));
				
				//Modify TCP TSecr back to jiffies
				//Don't disturb TCP. Wrong TCP timestamp echo reply may reset TCP connections
				*tsecr=htonl(jiffies);
				//*tsecr=htonl((unsigned int)usecs_to_jiffies(ntohl(*tsecr)));
			}
			
			//TCP length=Total length - IP header length
			tcplen=skb->len-(ip_header->ihl<<2);
			tcp_header->check=0;
			
			tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                  tcplen, ip_header->protocol,
                                  csum_partial((char *)tcp_header, tcplen, 0));
								  
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			
			return NF_ACCEPT;
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
        
	//PREROUTING
	nfho_incoming.hook=hook_func_in;					//function to call when conditions below met    
	nfho_incoming.hooknum=NF_INET_PRE_ROUTING;			//called in pre_routing
	nfho_incoming.pf = PF_INET;							//IPV4 packets
	nfho_incoming.priority = NF_IP_PRI_FIRST;			//set to highest priority over all other hook functions
	nf_register_hook(&nfho_incoming);					//register hook*/
	
	//Set initial average RTT to be 100us
	avg_rtt=100;
	
	
	printk(KERN_INFO "Start ICTCP kernel module\n");

	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	//Unregister two hooks
	nf_unregister_hook(&nfho_outgoing);  
	nf_unregister_hook(&nfho_incoming);
	
	printk(KERN_INFO "Stop ICTCP kernel module\n");

}
