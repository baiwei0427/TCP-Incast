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
#include "hash.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Driver module of Proactive ACK Control (PAC)");

#define MIN_RTT 100	 //Base RTT: 100 us
#define BUCKET 25000	//Base Bucket: min(2*MIN_RTT*C, Switch buffer size)
#define BUFFER 100000	//A conservative switch buffer size value: 100KB
#define RATE 120000000  //125000000 //125M Bytes persecond (1Gbps)

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)
//Delay 
static unsigned long delay_in_us = 100L;//40L
//Incoming traffic volume (bytes) in a timeslot (2RTT)
static int traffic=0;
//Incoming traffic with Congestion Experienced in a timeslot
static int ce=0;


//Tokens in bucket
static unsigned long tokens=0;
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
//Old time value
static struct timeval tv_old;
//lock
static spinlock_t globalLock;

//Function to calculate timer interval
static unsigned long time_of_interval(struct timeval tv_new,struct timeval tv_old)
{
	return (tv_new.tv_sec-tv_old.tv_sec)*1000000+(tv_new.tv_usec-tv_old.tv_usec);
}

//POSTROUTING for outgoing packets, enqueue packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;   //ip header struct
	struct tcphdr *tcp_header; //tcp header struct
	unsigned long flags;       //variable for save current states of irq
	int len;                   //len of traffic that ACK packet can trigger

	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}

	if(ip_header->protocol==IPPROTO_TCP) { //TCP packets
		
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		unsigned int dst_port=htons((unsigned short int) tcp_header->dest);
		//We only deal with ACK packets whose dst port is 5001 
		if(dst_port==5001) {

			spin_lock_irqsave(&globalLock,flags);
			
			//Request packet with payload can trigger 3MSS
			if(tcp_header->psh)
				len=4542;
			//else if(tcp_header->syn||tcp_header->fin)
			//	len=1514;
			else
				len=1514;
			//If there is no packet in the queue and tokens are enough
			if(tokens>=len&&q->size==0) {
				//Reduce tokens by packet size
				tokens=tokens-len;
				spin_unlock_irqrestore(&globalLock,flags);
				//spin_unlock_irq(&globalLock);
				//spin_unlock(&globalLock);
				return NF_ACCEPT;
			}

			//Else, we need to enqueue this packet
			int result=Enqueue_PacketQueue(q,skb,okfn);
			spin_unlock_irqrestore(&globalLock,flags);
			//spin_unlock_irq(&globalLock);
			//spin_unlock(&globalLock);

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
	return NF_ACCEPT;
}

static enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
{
	struct timeval tv;           //timeval struct used by do_gettimeofday
	unsigned long time_interval; //time interval
	ktime_t interval,now;  
	unsigned long flags;         //variable for save current states of irq
	unsigned int len;

	//Get current time
	do_gettimeofday(&tv);
	//Calculate interval	
	time_interval=time_of_interval(tv,tv_old);
	//Reset tv_old
	tv_old=tv;
	//Update tokens	
	tokens=tokens+(time_interval*RATE)/1000000;
	
	spin_lock_irqsave(&globalLock,flags);
	//spin_lock_irq(&globalLock);
	//spin_lock(&globalLock);
	while(1)
	{

		if(q->size>0) { //There are still some packets in queue 
			//printk(KERN_INFO "%u\n",len);
			//We assume an ACK can trigger two MSS packets
			if(q->packets[q->head].skb->len>52)
				len=4542;
			else
				len=1514;
			if(len<=tokens) { //There are enough tokens
				//Reduce tokens
				tokens=tokens-len;
				//Deuqueu packets
				Dequeue_PacketQueue(q);
			} else { //There are no enough tokens
				break;
			}
		} else { 
			break;
		}
	}
	//Toekns no larger then bucket size if there are no packets to transmit
	if(tokens>=BUCKET&&q->size==0)
		tokens=BUCKET;
	spin_unlock_irqrestore(&globalLock,flags);
	//spin_unlock_irq(&globalLock);
	//spin_unlock(&globalLock);

	interval = ktime_set(0, US_TO_NS(delay_in_us));
	now = ktime_get();
	hrtimer_forward(timer,now,interval);
	return HRTIMER_RESTART;
}

int init_module(void) 
{

	ktime_t ktime;
	//Initialize tokens
	tokens=0;
	//Initialize clock
	spin_lock_init(&globalLock);

	//Init PacketQueue
	q=vmalloc(sizeof(struct PacketQueue));
	Init_PacketQueue(q);

	//Init timer
	do_gettimeofday(&tv_old);

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
