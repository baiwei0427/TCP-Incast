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
//#include "hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Driver module of Proactive ACK Control (PAC)");

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)

//Delay: 1RTT 
static unsigned long delay_in_us = 100L;//40L
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


//Load module into kernel
int init_module(void);
//Unload module from kernel
void cleanup_module(void);
//PacketQueue pointer
static struct PacketQueue *q=NULL;
//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//Incoming packets PREROUTING
static struct nf_hook_ops nfho_incoming;
///High resolution timer
static struct hrtimer hr_timer;
//lock
static spinlock_t globalLock;

//Function to calculate timer interval
//static unsigned long time_of_interval(struct timeval tv_new,struct timeval tv_old)
//{
//	return (tv_new.tv_sec-tv_old.tv_sec)*1000000+(tv_new.tv_usec-tv_old.tv_usec);
//}

//POSTROUTING for outgoing packets, enqueue packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;   //ip header struct
	struct tcphdr *tcp_header; //tcp header struct
	unsigned int dst_port;	   //Desination tcp port
	int len;                   //len of traffic that ACK packet can trigger
	unsigned long flags;       //variable for save current states of irq
	int result=0;

	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}

	if(ip_header->protocol==IPPROTO_TCP) { //TCP packets
		
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		dst_port=htons((unsigned short int) tcp_header->dest);
		//We only deal with ACK packets whose dst port is 5001 
		if(dst_port==5001) {
			
			//Request packet with payload can trigger 3MSS
			if(tcp_header->psh)
				len=4542;
			else if(tcp_header->syn)
				len=100;
			else
				len=1615;
			//If there is no packet in the queue and tokens are enough
			if(bucket-tokens>=len&&q->size==0) {
				spin_lock_irqsave(&globalLock,flags);
				//Increase in-flight traffic value
				tokens+=len;
				spin_unlock_irqrestore(&globalLock,flags);
				//spin_unlock_irq(&globalLock);
				//spin_unlock(&globalLock);
				return NF_ACCEPT;
			}
			
			//Else, we need to enqueue this packet
			spin_lock_irqsave(&globalLock,flags);
			result=Enqueue_PacketQueue(q,skb,okfn);
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

//PREROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;   //ip header struct
	struct tcphdr *tcp_header; //tcp header struct
	unsigned int src_port;	   //source TCP port
	unsigned long flags;       //variable for save current states of irq
	
	ip_header=(struct iphdr *)skb_network_header(skb);
	
	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}
	
	if(ip_header->protocol==IPPROTO_TCP) { //TCP packets
	
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		src_port=htons((unsigned short int) tcp_header->source);
		
		if(src_port==5001)
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

static enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
{
	//struct timeval tv;           //timeval struct used by do_gettimeofday
	ktime_t interval,now;  
	unsigned long flags;         //variable for save current states of irq
	unsigned int len;
	
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
			tokens=bucket*3/5*traffic/25000*2*traffic/(2*traffic-ce);
		}
		
		if(traffic==0)
		{
			tokens=0;
		}
		if(traffic>1000)
		{
			printk(KERN_INFO "Reset in-flight traffic to %lu\n", tokens);
		}
		traffic=0;
		ce=0;
	}
	while(1)
	{

		if(q->size>0) { //There are still some packets in queue 
			
			if(q->packets[q->head].skb->len>60) //SYN packets
				len=100;
			else if(q->packets[q->head].skb->len>52) //Request packets
				len=4542;
			else //Normal ACK packets
				len=1615;
				
			if(bucket-tokens>=len) { //There is still enough space 
			
				spin_lock_irqsave(&globalLock,flags);
				//Increase in-flight traffic value
				tokens+=len;
				//Dequeue packets
				Dequeue_PacketQueue(q);
				spin_unlock_irqrestore(&globalLock,flags);
				
			} else { //There is no enough space
				break;
			}
		} else { 
			break;
		}
	}

	interval = ktime_set(0, US_TO_NS(delay_in_us));
	now = ktime_get();
	hrtimer_forward(timer,now,interval);
	return HRTIMER_RESTART;
}

int init_module(void) 
{

	ktime_t ktime;
	//Initialize status
	status=0;
	//Initialize in-flight traffic as zero
	tokens=0;
	//Initialize max in-flight traffic
	bucket=80000;
	//Initialize clock
	spin_lock_init(&globalLock);

	//Init PacketQueue
	q=vmalloc(sizeof(struct PacketQueue));
	Init_PacketQueue(q);

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
	
	printk(KERN_INFO "Install PAC kernel module\n");
	return 0;
}

void cleanup_module(void) 
{
	int ret;

	ret = hrtimer_cancel( &hr_timer );
	if (ret) {
		printk("The timer was still in use...\n");
	} 

	nf_unregister_hook(&nfho_outgoing);
	nf_unregister_hook(&nfho_incoming);
	Free_PacketQueue(q);
	printk(KERN_INFO "Uninstall PAC kernel module\n");
	
}
