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
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>

// This program is to measure goodput during TCP incast congestion
// Measuring goodput in application level is not precise.
// Many parameters (e.g. delayed ACK) may influence final results
// To avoid this problem, we just use this kernel module to measure throughput  

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei wbaiab@ust.hk");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Driver module to measure goodput of TCP incast congestion");

//Incoming packets in NF_IP_LOCAL_IN
static struct nf_hook_ops nfho_incoming;

//flag denoting whether measurement has been started
//If measurement has not been started yet, flag=0
//Else, flag=1
static int flag;
//Network traffic size in total
static unsigned long size;
//incast start time
static struct timeval tv_start;       
//incast end time
static struct timeval tv_end;          

//Match function
//If the packet targerts at TCP port 5001, return (TCP payload size+1)
//Else, return 0
static unsigned int match(struct sk_buff *skb)
{	
	 struct iphdr *ip_header;   //ip header struct
     struct tcphdr *tcp_header; //tcp header struct

	 ip_header=(struct iphdr *)skb_network_header(skb);
	 
	 //The packet is not ip packet (e.g. ARP or others)
	 if (!ip_header)
	 {
		 return 0;
	 }

	 if(ip_header->protocol==IPPROTO_TCP) //TCP
	 {
		 tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		 unsigned int dst_port=htons((unsigned short int) tcp_header->dest);

		//TCP dstport=5001
		if(dst_port==5001)
		{
			return skb->len;					
		}
	 }
	
	 return 0;
}

//NF_LOCAL_IN hook function 
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	//We don't listen on eth0
	if(strcmp(in->name,"eth0")!=0)
	{
		int result=match(skb);
		if(result==0)
		{
			return NF_ACCEPT;
		}
		//An effective packet comes in
		else
		{
			//The measurement has not been started yet
			//We need to start measurement right now!
			if(flag==0)
			{
				//Reset flag
				flag=1;
				//Reset traffic amount to be zero
				size=0;
				//Get measurement start/end time
				do_gettimeofday(&tv_start);
				do_gettimeofday(&tv_end);
			}
				
			//We ignore packets without any TCP payload data (including delayed ACK packets)
			if(result>100)
			{
				//Increase the value of traffic amount
				size=size+result-14-20-20-12;
				//Update tv_end
				do_gettimeofday(&tv_end);
			}
		}

	}
	return NF_ACCEPT;
}	

static void reset()
{
	//Init some variables
	flag=0;
	size=0;
}

//Print measurement result
static void print_result()
{
	unsigned long duration=(tv_end.tv_sec-tv_start.tv_sec)*1000000+tv_end.tv_usec-tv_start.tv_usec;
	printk(KERN_INFO "Duration: %lu microseconds\n",duration);
	printk(KERN_INFO "Traffic amount: %lu\n",size);
	if(duration>0 &&size>0)
	{
		printk(KERN_INFO "The throughput is: %lu Mbps\n",size*8/duration);
	}
}

//Called when module loaded using 'insmod'
int init_module()
{
	reset();

	//NF_LOCAL_IN Hook
	nfho_incoming.hook = hook_func_in;                    //function to call when conditions below met
	nfho_incoming.hooknum = NF_INET_LOCAL_IN;             //called in NF_IP_LOCAL_IN
	nfho_incoming.pf = PF_INET;                           //IPV4 packets
	nfho_incoming.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
	nf_register_hook(&nfho_incoming);                     //register hook

	printk(KERN_INFO "The measurement kernel module has been initiated\n");
	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	nf_unregister_hook(&nfho_incoming);
	print_result();
	printk(KERN_INFO "The measurement kernel module has been removed\n");
}