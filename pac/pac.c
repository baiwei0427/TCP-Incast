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

static char *param_dev=NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate PAC");
module_param(param_dev, charp, 0);

//FlowTable
static struct FlowTable ft;
//Lock for flow table 
static spinlock_t tableLock;
//Lock for global information (e.g. tokens)
static spinlock_t globalLock;

//The number of concurrent connections
static unsigned int connections;
//Global update time
static unsigned int last_update;
//Total value of all RTT samples (us)
static unsigned long total_rtt;
//Sample RTT numbers
static unsigned long samples;
//Average RTT (us)
static unsigned long avg_rtt;
//Average throughput (Mbps)
static unsigned int avg_throughput;

//Incoming traffic volume (bytes) in a timeslot (RTT)
static unsigned long traffic=0;
//Incoming traffic with ECN marking (Congestion Experienced) in a timeslot (RTT)
static unsigned long ecn_traffic=0;
//Tokens: estimation of in-flight traffic 
static unsigned long tokens=0;
//Threshold for in-flight traffic
static unsigned long bucket=0;

//Load module into kernel
int init_module(void);
//Unload module from kernel
void cleanup_module(void);
//PacketQueue pointer
static struct PacketQueue *q=NULL;
//Hook for outgoing packets at POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//Hook for incoming packets at PREROUTING
static struct nf_hook_ops nfho_incoming;
///High resolution timer
static struct hrtimer hr_timer;


//POSTROUTING for outgoing packets, enqueue packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip_header;       //IP header structure
    struct tcphdr *tcp_header;  //TCP header structure
    struct Flow f;
    struct Info* info_pointer=NULL;
    unsigned int trigger=0;          //The volume of traffic that ACK packet can trigger
    unsigned long flags;               //variable for save current states of irq
    unsigned int ack;                    //The ACK number of this packet
    unsigned int payload_len;  //TCP payload length
    int result=0;

    if(!out)
    {
        return NF_ACCEPT;
    }
    
    if(strcmp(out->name,param_dev)!=0)
    {
        return NF_ACCEPT;
    }    
    
	ip_header=(struct iphdr *)skb_network_header(skb);
	//The packet is not ip packet (e.g. ARP or others)
    
	if (!ip_header)
	{
		return NF_ACCEPT;
	}

	if(ip_header->protocol==IPPROTO_TCP) //TCP packets
    {	
        tcp_header=(struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        payload_len= (unsigned int)ntohs(ip_header->tot_len)-(ip_header->ihl<<2)-(tcp_header->doff<<2);
        f.local_ip=ip_header->saddr;
        f.remote_ip=ip_header->daddr;
        f.local_port=ntohs(tcp_header->source);
        f.remote_port=ntohs(tcp_header->dest);
        //If this is SYN packet, a new Flow record should be inserted into Flow table
		if(tcp_header->syn)
		{
            f.i.srtt=MIN_RTT;
            f.i.phase=SLOW_START;
            f.i.bytes_sent_latest=0;
            f.i.bytes_sent_total=0;
            f.i.last_ack=ntohl(tcp_header->ack_seq);
            f.i.last_seq=0;
            f.i.last_update=get_tsval();
            spin_lock_irqsave(&tableLock,flags);
            if(Insert_Table(&ft,&f)==0)
            {
                printk(KERN_INFO "Insert fails\n");
            }
            spin_unlock_irqrestore(&tableLock,flags);
            //We expect an incoming SYN or ACK packet
            trigger=MIN_PKT_LEN;
        }
        else if(tcp_header->ack)
        {
            ack=ntohl(tcp_header->ack_seq);
            Init_Info(&(f.i));
            spin_lock_irqsave(&tableLock,flags);
            info_pointer=Search_Table(&ft,&f);
            spin_unlock_irqrestore(&tableLock,flags);
            //Update per-flow information now
            if(info_pointer!=NULL)
            {
                //If this packet is the first ACK packet since last_ack==0
                if(info_pointer->last_ack==0)
                {
                    info_pointer->last_ack=ack;
                    //TCP payload length>0
                    if(payload_len>0)
                    {
                        trigger=MIN_WIN*(MSS+54);
                    }
                    else
                    {
                        trigger=MIN_PKT_LEN;
                    }
                }
                else 
                {
                    //If the packet is ECE, this TCP flow goes into congestion avoidance
                    if(tcp_header->ece)
                    {
                        info_pointer->phase=CONGESTION_AVOIDANCE;
                    }   
                    //If the ACK number of current packet is larger than the latest ACK number of this flow
                    if(is_larger(ack,info_pointer->last_ack)==1)
                    {
                        //The volume of data cumulatively acknowledged by this ACK packet
                        trigger=cumulative_ack(ack,info_pointer->last_ack);
                        info_pointer->last_ack=ack;
                    }
                    //Calculate the volume of data triggered by this ACK packet
                    if(trigger>0)
                    {
                        //Slow start: trigger=ack2-ack1+MSS
                        if(info_pointer->phase==SLOW_START)
                        {
                            trigger=(trigger+MSS)*(MSS+54)/MSS;
                        }
                        //Congestion avoidance
                        else
                        {
                            trigger=(trigger+MSS/MIN_WIN)*(MSS+54)/MSS;
                        }
                    }
                    //The first request packet whose TCP payload length>0
                    else if(payload_len>0)
                    {
                        trigger=MIN_WIN*(MSS+54);
                    }
                    else 
                    {
                        trigger=MIN_PKT_LEN;
                    }
                }
            }
            else
            {
                trigger=MIN_PKT_LEN;
            }
        }
        else
        {
            trigger=MIN_PKT_LEN;
        }
        //When we observe trigger>=bucket, the kernel module will be crashed
        if(trigger>=bucket)
        {
            printk(KERN_INFO "Alert: the trigger is %u which is larger than the in-flight traffic threshold\n",trigger);
        }
		//Modify TCP timestamp for outgoing packets
		tcp_modify_outgoing(skb,0,get_tsval());
		        
        //If there is no packet in the queue and tokens are enough
        if(bucket-tokens>=trigger&&q->size==0) 
        {
            //Increase in-flight traffic value
            spin_lock_irqsave(&globalLock,flags);
			tokens+=trigger;
            spin_unlock_irqrestore(&globalLock,flags);
            //printk(KERN_INFO "Current in-flight traffic is %lu\n",tokens);
			return NF_ACCEPT;
		}
		//Else, we need to enqueue this packet
		result=Enqueue_PacketQueue(q,skb,okfn,trigger);

		if(result==1)//Enqueue successfully 
        { 
			//printk(KERN_INFO "Enqueue a packet\n");
			return NF_STOLEN;
        } 
        else//No enough space in queue 
        {       
			printk(KERN_INFO "No enough space in queue\n");
			return NF_DROP;
		}
        return NF_ACCEPT;
	}
	return NF_ACCEPT;
}

//PREROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;             //IP header structure
	struct tcphdr *tcp_header;        //TCP header structure
    struct Flow f;
    unsigned long flags;
	struct Info* info_pointer=NULL;
	unsigned int rtt=0;		                //Sample RTT value
    unsigned int payload_len;        //TCP payload length
	    
    if(!in)
    {
        return NF_ACCEPT;
    }
    
    if(strcmp(in->name,param_dev)!=0)
    {
        return NF_ACCEPT;
    }    
        
	ip_header=(struct iphdr *)skb_network_header(skb);
	
	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
	{
		return NF_ACCEPT;
	}
	
    //TCP packets
	if(ip_header->protocol==IPPROTO_TCP)   
    {
        tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        payload_len= (unsigned int)ntohs(ip_header->tot_len)-(ip_header->ihl<<2)-(tcp_header->doff<<2);        
        //Note that: source and destination should be changed !!!
        f.local_ip=ip_header->daddr;
        f.remote_ip=ip_header->saddr;
        f.local_port=ntohs(tcp_header->dest);
        f.remote_port=ntohs(tcp_header->source);
        Init_Info(&(f.i));
        //Delete flow entry when we observe FIN or RST packets 
        if(tcp_header->fin||tcp_header->rst)
        {
            spin_lock_irqsave(&tableLock,flags);
			if(Delete_Table(&ft,&f)==0)
            {
                printk(KERN_INFO "Delete fails\n");
            }
            spin_unlock_irqrestore(&tableLock,flags);
        }
        else
        {
            //Get reverse RTT
            rtt=tcp_modify_incoming(skb);
            printk(KERN_INFO "%u\n", rtt);
            //Search flow information in the table
            spin_lock_irqsave(&tableLock,flags);
            info_pointer=Search_Table(&ft,&f);
            spin_unlock_irqrestore(&tableLock,flags);    
            //Update per-flow information
            if(info_pointer!=NULL)
            {
                //Update smooth RTT
                info_pointer->srtt=RTT_SMOOTH*info_pointer->srtt/1000+(1000-RTT_SMOOTH)*rtt/1000;
                //Update bytes sent
                if(info_pointer->bytes_sent_total<=4294900000)
                {
                    info_pointer->bytes_sent_total+=skb->len-(ip_header->ihl<<2)-tcp_header->doff*4;
                }
                //Update latest sequence number 
                if(payload_len>0&&is_larger(tcp_header->seq+payload_len-1,info_pointer->last_seq)==1)
                {
                    info_pointer->last_seq=tcp_header->seq+payload_len-1;
                }     
            }
        }
        spin_lock_irqsave(&globalLock,flags);
        //Incoming traffic in this timeslot
		traffic+=skb->len;
		//ECN marking traffic
		if(ip_header->tos==0x03)
		{
			//Congestion Experienced traffic in this timeslot
			ecn_traffic+=skb->len;
		}
        if(tokens>=skb->len)
        {
            tokens-=skb->len;
        }
        else
        {
            tokens=0;
        }
        //if(tokens>0)
        //    printk(KERN_INFO "Current in-flight traffic is %lu\n",tokens);
        total_rtt+=rtt;
        samples++;
        spin_unlock_irqrestore(&globalLock,flags);   
    }	
	return NF_ACCEPT;
}

static enum hrtimer_restart my_hrtimer_callback( struct hrtimer *timer )
{
	//struct timeval tv;           //timeval struct used by do_gettimeofday
	ktime_t interval,now;  
	unsigned long flags;         //variable for save current states of irq
	unsigned int len;
    unsigned int time=0;       //Time interval to measure throughput
    unsigned int current_time=0;
    unsigned long int throughput=0; 	//Incoming throughput in the latest slot
    
    current_time=get_tsval();
    time=current_time-last_update;
    if(time>avg_rtt)
    {
        last_update=current_time;
        //Correct in-flight traffic overestimation
        //Calculate incoming throughput (Mbps)
        throughput=traffic*8/time;
        spin_lock_irqsave(&globalLock,flags);    
        if(throughput<ALPHA&&2*traffic>ecn_traffic)//*avg_throughput/1000&&2*traffic>ecn_traffic)
        {
            tokens=min(tokens,bucket*throughput/avg_throughput*2*traffic/(2*traffic-ecn_traffic));
            if(tokens>0)
                printk(KERN_INFO "Current throughput is %lu Mbps, we reset in-flight traffic to %lu\n",throughput,tokens);
        }
        //Reset global information
        if(samples>0)
        {
            avg_rtt=min(max(MIN_RTT,total_rtt/samples),MAX_RTT);
        }
        else
        {
            avg_rtt=MIN_RTT;
        }
        //avg_throughput=THROUGHPUT_SMOOTH*avg_throughput/1000+(1000-THROUGHPUT_SMOOTH)*throughput/1000;
        traffic=0;
        ecn_traffic=0;
        total_rtt=0;
        samples=0;
        spin_unlock_irqrestore(&globalLock,flags);  
    }
            
	while(1)
	{
		if(q->size>0) //There are still some packets in queue 	
        { 			
            len=q->packets[q->head].trigger;
			if(bucket-tokens>=len)  
            { 
                //Increase in-flight traffic value
				tokens+=len;
				//spin_lock_irqsave(&globalLock,flags);
                //Dequeue packets
                Dequeue_PacketQueue(q);
                //spin_unlock_irqrestore(&globalLock,flags);
                printk(KERN_INFO "Current in-flight traffic is %lu\n",tokens);
			} 
            else 
            { 
				break;
			}
		} 
        else 
        { 
			break;
		}
	}
	interval = ktime_set(0, US_TO_NS(DELAY_IN_US));
	now = ktime_get();
	hrtimer_forward(timer,now,interval);
	return HRTIMER_RESTART;
}

int init_module(void) 
{
    int i=0;
     //Get interface
    if(param_dev==NULL) 
    {
        printk(KERN_INFO "PAC: not specify network interface (eth1 by default). \n");
        param_dev = "eth1\0";
	}
    // trim 
	for(i = 0; i < 32 && param_dev[i] != '\0'; i++) 
    {
		if(param_dev[i] == '\n') 
        {
			param_dev[i] = '\0';
			break;
		}
	}
    
	ktime_t ktime;
	//Initialize max in-flight traffic
	bucket=BUFFER_SIZE;
    //Initialize in-flight traffic as zero
	tokens=0;

    //Get current time as the latest update time 
	last_update=get_tsval();	
    total_rtt=0;					
	samples=0;						
	avg_rtt=MIN_RTT;	
    //1000Mbps 
    avg_throughput=1000;
    
	//Initialize PacketQueue
	q=vmalloc(sizeof(struct PacketQueue));
	Init_PacketQueue(q);
    
    //Initialize FlowTable
	Init_Table(&ft);	
    //Initialize lock for table
    spin_lock_init(&tableLock);
    //Initialize lock for global information
    spin_lock_init(&globalLock);
    
    //Init Timer
	ktime = ktime_set( 0, US_TO_NS(DELAY_IN_US) );
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
	if (ret)
    {
		printk("The timer was still in use...\n");
	} 

	nf_unregister_hook(&nfho_outgoing);
	nf_unregister_hook(&nfho_incoming);
	Free_PacketQueue(q);
    //Clear flow table
	//Print_Table(&ft);
	Empty_Table(&ft);
	printk(KERN_INFO "Uninstall PAC kernel module\n");
	
}
