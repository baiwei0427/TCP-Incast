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
#include <linux/errno.h>
#include <linux/timer.h>

#include "hash.h"
#include "queue.h" 
#include "params.h"
#include "network_func.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.1");
MODULE_DESCRIPTION("Kernel module of Proactive ACK Control (PAC)");

char *param_dev=NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate PAC");
module_param(param_dev, charp, 0);

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)
//Slow start
#define SLOW_START 0
//Congestion avoidance
#define CONGESTION_AVOIDANCE 1

//Global update time
static unsigned int last_update;
//FlowTable
static struct FlowTable ft;
//Global Lock (For table)
static spinlock_t globalLock;

//Delay: 1RTT 
static unsigned long delay_in_us = MIN_RTT;
//Incoming traffic volume (bytes) in a timeslot (RTT)
static unsigned long traffic=0;
//Incoming traffic with Congestion Experienced in a timeslot
static unsigned long ce_traffic=0;
//Tokens: estimation of in-flight traffic 
static unsigned long tokens=0;
//Bucket (maximum in-flight traffic value)
static unsigned long bucket=BUFFER_SIZE;


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



//POSTROUTING for outgoing packets, enqueue packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;        //IP header structure
	struct tcphdr *tcp_header;  //TCP header structure
    struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int trigger;               //The size of traffic that ACK packet can trigger
	unsigned long flags;               //variable for save current states of irq
	int result=0;

    if(!out)
        return NF_ACCEPT;
        
    if(strcmp(out->name,param_dev)!=0)
        return NF_ACCEPT;
        
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}

	if(ip_header->protocol==IPPROTO_TCP) { //TCP packets
		
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
		//If this is SYN packet, a new Flow record should be inserted into Flow table
		if(tcp_header->syn)
		{
            f.local_ip=ip_header->saddr;
			f.remote_ip=ip_header->daddr;
			f.local_port=ntohs(tcp_header->source);
			f.remote_port=ntohs(tcp_header->dest);
            f.i.rtt=MIN_RTT;
            f.i.phase=SLOW_START;
            f.i.bytes_sent_latest=0;
            f.i.bytes_sent_total=0;
            f.i. last_ack=ntohl(tcp_header->ack_seq);
            f.i.last_update=get_tsval();
            
            spin_lock_irqsave(&globalLock,flags);
            if(Insert_Table(&ft,&f)==0)
				printk(KERN_INFO "Insert fails\n");
             spin_unlock_irqrestore(&globalLock,flags);
            trigger=MIN_PKT_LEN;
        }
        else
        {
            f.local_ip=ip_header->saddr;
			f.remote_ip=ip_header->daddr;
			f.local_port=ntohs(tcp_header->source);
			f.remote_port=ntohs(tcp_header->dest);
        }
        
        
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
			tokens=bucket*traffic/25000*2*traffic/(2*traffic-ce);
			if(tokens>bucket)
				tokens=bucket;
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
