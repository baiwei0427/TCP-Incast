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
MODULE_DESCRIPTION("Driver module of Proactive ACK Control (PAC)");

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)
#define MSS 1460

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


//Function to calculate microsecond-granularity TCP timestamp value
static unsigned int get_tsval(void)
{	
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

//Function to modify microsecond-granularity TCP timestamp option back to millisecond-granularity
//If successfully, return the value of sample RTT
//Else, return 0
//Note: we disable TCP window scaling 
static unsigned int tcp_modify_incoming(struct sk_buff *skb)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned char *tcp_opt=NULL;		  //TCP option
	unsigned int *tsecr=NULL;			  //TCP timestamp option
	int tcplen=0;						  //Length of TCP
	unsigned int rtt=0;					  //Sample RTT
	
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
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
		rtt=get_tsval()-ntohl(*tsecr);
		//printk(KERN_INFO "RTT sample: %u\n",rtt);
				
		//Modify TCP TSecr back to jiffies
		//Don't disturb TCP. Wrong TCP timestamp echo reply may reset TCP connections
		*tsecr=htonl(jiffies);
	}
	else
	{
		return 0;
	}
			
	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
			
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
                                  tcplen, ip_header->protocol,
                                  csum_partial((char *)tcp_header, tcplen, 0));
								  
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	return rtt;
} 

//Function:
//	i) modify millisecond-granularity TCP timestamp option to microsecond-granularity time
// ii) modify TCP receive window (if win isn't 0)
//If successfully, return 1 Else, return 0
static unsigned int tcp_modify_outgoing(struct sk_buff *skb, unsigned short win)
{
	struct iphdr *ip_header=NULL;		//IP  header structure
	struct tcphdr *tcp_header=NULL;     //TCP header structure
	unsigned char *tcp_opt=NULL;	 	//TCP option
	unsigned int *tsval=NULL;	     	//TCP timestamp option
	int tcplen=0;                    	//Length of TCP
	
	if (skb_linearize(skb)!= 0) 
	{
		return 0;
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
	else
	{
		return 0;
	}
	
	//Modify TCP window if win isn't 0
	if(win>0)
	{
		tcp_header->window=htons(win*MSS);
	}

	//TCP length=Total length - IP header length
	tcplen=skb->len-(ip_header->ihl<<2);
	tcp_header->check=0;
			
	tcp_header->check = csum_tcpudp_magic(ip_header->saddr, ip_header->daddr,
											tcplen, ip_header->protocol,
											csum_partial((char *)tcp_header, tcplen, 0));
								  									 
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	
	return 1;
}

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
			
			//Modify TCP timestamp for outgoing packets
			tcp_modify_outgoing(skb,0);
			
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
	unsigned int rtt;		   //Sample RTT value
	
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
			//Get reverse RTT
			rtt=tcp_modify_incoming(skb);
			//printk(KERN_INFO "%u\n", rtt);
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
			tokens=bucket*1/2*traffic/25000*2*traffic/(2*traffic-ce);
		}
		
		if(traffic==0)
		{
			tokens=0;
		}
		//if(traffic>1000)
		//{
		//	printk(KERN_INFO "Reset in-flight traffic to %lu\n", tokens);
		//}
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
	bucket=70000;
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
