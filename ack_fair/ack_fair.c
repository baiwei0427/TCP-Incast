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
#include <asm/uaccess.h> 
#include <linux/hrtimer.h>
#include <linux/ktime.h>

#include "queue.h" 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Driver module of Fair Sharing ACK Shaper");

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)
//PacketQueue numbers
#define QUEUE_NUM 4

//Delay: 1RTT 
static unsigned long delay_in_us = 100L;
//Incoming traffic volume (bytes) in a timeslot (2RTT)
static unsigned long traffic=0;
//Incoming traffic with Congestion Experienced in a timeslot
static unsigned long ce=0;
//Status: First RTT (0) Second RTT (1)
static unsigned int status=0;
//Tokens (in-flight traffic) 
static unsigned long tokens=0;
//Bucket (maximum in-flight traffic value)
static unsigned long bucket=60000; 
//Starting point fro RR algorithm
static unsigned int start=0;

//Load module into kernel
int init_module(void);
//Unload module from kernel
void cleanup_module(void);
//PacketQueue array pointer, we have multiple PacketQueue to store ACKs of different flows
static struct PacketQueue **q=NULL;
//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//Incoming packets PREROUTING
static struct nf_hook_ops nfho_incoming;
///High resolution timer
static struct hrtimer hr_timer;
//lock
static spinlock_t globalLock;

//POSTROUTING for outgoing packets, enqueue packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;   //IP header structure
	struct tcphdr *tcp_header; //TCP header structure
	unsigned int src_port;	   //Source TCP port
	unsigned int dst_ip;	   //Destination IP address
	unsigned long flags;       //variable for save current states of irq
	int result=0;

	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}

	if(ip_header->protocol==IPPROTO_TCP) //TCP packets
	{ 
		//Get Destination IP Address
		dst_ip=ip_header->daddr;
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		//Get TCP Source Port
		src_port=htons((unsigned short int) tcp_header->source);
		//We only deal with ACK packets whose src port is 5001 (iperf)
		if(src_port==5001) {
			spin_lock_irqsave(&globalLock,flags);
			//Enqueue this packet to Per-flow ACK queue
			result=Enqueue_PacketQueue(q[(dst_ip/256/256/256)%QUEUE_NUM],skb,okfn);
			spin_unlock_irqrestore(&globalLock,flags);

			if(result==1) { //Enqueue successfully
				//printk(KERN_INFO "Enqueue a packet\n");
				return NF_STOLEN;

			} else {        //No enough space in queue
				printk(KERN_INFO "No enough space in queue\n");
				return NF_DROP;
			}
		}
	}
	return NF_ACCEPT;
}

//If all of the queues (QUEUE_NUM) are empty ,return 1
//Else return 0
static int is_empty(struct PacketQueue **queues)
{
	int i=0;
	for(i=0;i<QUEUE_NUM;i++)
	{
		if(queues[i]->size>0)
			return 0;
	}
	return 1;
}

static enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
{
	ktime_t interval,now;  
	unsigned long flags;         //variable for save current states of irq
	int i=start;				 //Get the starting point of RR
	unsigned int len=1815;
	
	if(status==0)
	{
		status=1;
	}
	else
	{
		status=0;
		//Reset in-flight traffic based on incoming traffic and ECN
		if(traffic<20000&&traffic>0&&2*traffic>ce)
		{
			tokens=bucket*1/2*traffic/25000*2*traffic/(2*traffic-ce);
		}
		
		if(traffic==0)
		{
			tokens=0;
		}
		traffic=0;
		ce=0;
	}
	
	while(1)
	{
		if(bucket-tokens<len) //No enough network capacity for in-flight traffic
		{
			start=i%QUEUE_NUM;	//Reset starting point of RR
			break;
		}
		else if(is_empty(q)>0) //No ACK packets in queues, jump out of the while loop
		{
			start=i%QUEUE_NUM;	//Reset starting point of RR
			break;
		}
			
		if(q[i%QUEUE_NUM]->size>0&&bucket-tokens>=len) { //There are still some packets in queue[i] 
			spin_lock_irqsave(&globalLock,flags);
			//Increase in-flight traffic value
			tokens+=len;
			//Dequeue packets
			Dequeue_PacketQueue(q[i%QUEUE_NUM]);
			spin_unlock_irqrestore(&globalLock,flags);
		}
		i++;
	}
	
	interval = ktime_set(0, US_TO_NS(delay_in_us));
	now = ktime_get();
	hrtimer_forward(timer,now,interval);
	return HRTIMER_RESTART;
}

//PREROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;   //IP header struct
	struct tcphdr *tcp_header; //TCP header struct
	unsigned int dst_port;	   //destination TCP port
	unsigned long flags;       //variable for save current states of irq
	
	ip_header=(struct iphdr *)skb_network_header(skb);
	
	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}
	
	if(ip_header->protocol==IPPROTO_TCP) { //TCP packets
	
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		if(dst_port==5001)
		{
			//Incoming traffic in this timeslot
			traffic+=skb->len;
			//CE bit=11
			if(ip_header->tos==0x03&&skb->len>100)
			{
				//Congestion Experienced traffic in this timeslot
				ce+=skb->len;
			}
			//Reduce in-flight traffic value 
			spin_lock_irqsave(&globalLock,flags);
			tokens-=skb->len;
			spin_unlock_irqrestore(&globalLock,flags);
		}
	}
	
	return NF_ACCEPT;
}

int init_module(void) 
{
	int i=0;
	ktime_t ktime;
	//Initialize starting point of RR
	start=0;
	//Initialize status
	status=0;
	//Initialize in-flight traffic as zero
	tokens=0;
	//Initialize max in-flight traffic: min(Base BDP+switch buffer/2, switch buffer)
	bucket=60000;
	//Initialize clock
	spin_lock_init(&globalLock);

	//Init PacketQueue array
	q=vmalloc(QUEUE_NUM*sizeof(struct PacketQueue*));
	//Init each PacketQueue
	for(i=0;i<QUEUE_NUM;i++)
	{
		q[i]=vmalloc(sizeof(struct PacketQueue));	
		Init_PacketQueue(q[i]);
	}

	ktime = ktime_set( 0, US_TO_NS(delay_in_us) );
	hrtimer_init( &hr_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
	hr_timer.function = &my_hrtimer_callback;
	hrtimer_start( &hr_timer, ktime, HRTIMER_MODE_REL );

    //POSTROUTING
	nfho_outgoing.hook = hook_func_out;                   	//function to call when conditions below met
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;         	//called in post_routing
	nfho_outgoing.pf = PF_INET;     						//IPV4 packets
	nfho_outgoing.priority = NF_IP_PRI_FIRST;             	//set to highest priority over all other hook functions
	nf_register_hook(&nfho_outgoing);                     	//register hook*/
	
	//PREROUTING
	nfho_incoming.hook=hook_func_in;						//function to call when conditions below met    
	nfho_incoming.hooknum=NF_INET_PRE_ROUTING;				//called in pre_routing
	nfho_incoming.pf = PF_INET;								//IPV4 packets
	nfho_incoming.priority = NF_IP_PRI_FIRST;				//set to highest priority over all other hook functions
	nf_register_hook(&nfho_incoming);						//register hook*/
	
	printk(KERN_INFO "Install Fair Sharing ACK Shaper kernel module\n");
	return 0;
}

void cleanup_module(void) 
{
	int ret;
	int i=0;

	ret = hrtimer_cancel( &hr_timer );
	if (ret) {
		printk("The timer was still in use...\n");
	} 

	nf_unregister_hook(&nfho_outgoing);
	nf_unregister_hook(&nfho_incoming);
	
	for(i=0;i<QUEUE_NUM;i++)
	{
		Free_PacketQueue(q[i]);
		vfree(q[i]);
	}
	vfree(q);
	printk(KERN_INFO "Uninstall Fair Sharing ACK Shaper kernel module\n");
	
}
