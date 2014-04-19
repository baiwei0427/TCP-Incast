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

#define MSS 1460				//MSS: 1460 bytes
#define MIN_RTT 100				//Base RTT: 100 us. This is initial value of srtt of each flow
#define MIN_RWND 2				//Minimal Window: 2MSS for ICTCP
#define MAX_RWND 40				//Maximum Window: 40MSS 
#define FIRST_SUBSLOT 0			//Status in first subslot
#define SECOND_SUBSLOT 1 		//Status in second subslot
#define US_TO_NS(x)	(x * 1E3L)  //microsecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)  //millisecond to nanosecond

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.0");
MODULE_DESCRIPTION("Kernel module in Linux for ICTCP");

//Glbal update time
static unsigned int last_update;
//Global Lock (For table)
static spinlock_t globalLock;
//Global statistic locak
//static spinlock_t statisticLock;
//Global Status: FIRST_SUBSLOT (0) or SECOND_SUBSLOT (1)
static unsigned short globalstatus; 

//FlowTable
static struct FlowTable ft;

//Total value of all RTT samples (us)
static unsigned long total_rtt;
//Sample RTT numbers
static unsigned long samples;
//Average RTT (us)
static unsigned long avg_rtt;
//Total traffic volume in latest RTT
static unsigned long total_traffic;
//Free capacity for flows to increase window
static unsigned long capacity;


//Sum of windows of all connections
//static unsigned int total_wind;
//Total concurrent connection numbers
static unsigned int connections;

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//Incoming packets PREROUTING
static struct nf_hook_ops nfho_incoming;

//Function to calculate microsecond-granularity TCP timestamp value
static unsigned int get_tsval(void)
{	
	return (unsigned int)(ktime_to_ns(ktime_get())>>10);
}

//Function:
//	i) modify millisecond-granularity TCP timestamp option back to microsecond-granularity
// ii) modify TCP receive window
//If successfully, return 1 Else, return 0
static unsigned int tcp_modify_outgoing(struct sk_buff *skb, unsigned short win)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned char *tcp_opt=NULL;	 //TCP option
	unsigned int *tsval=NULL;	     //TCP timestamp option
	int tcplen=0;                    //Length of TCP
	
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

//Function to modify microsecond-granularity TCP timestamp option back to millisecond-granularity
//If successfully, return the value of sample RTT
//Else, return 0
static unsigned int tcp_modify_incoming(struct sk_buff *skb)
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned char *tcp_opt=NULL;	 //TCP option
	unsigned int *tsecr=NULL;	     //TCP timestamp option
	int tcplen=0;                    //Length of TCP
	unsigned int rtt=0;				 //Sample RTT
	
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

//POSTROUTING for outgoing packets
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         //IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned short int dst_port;     	  //TCP destination port
	//unsigned short int src_port;	 	  //TCP source port
	struct Flow f;
	struct Info* info_pointer=NULL;
	//unsigned short reduce=0;	 	 //whether the window has been reduced due to fairness problem
	unsigned long flags;         	 //variable for save current states of irq
	unsigned long tmp=0;
	unsigned short increase=0;		 //Whether this flow's rwnd has been increased
	
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
		if(dst_port==5001)//||src_port==5001)
		{
			if(tcp_header->syn)
			{
				//If this is SYN packet, a new Flow record should be inserted into Flow table
				f.src_ip=ip_header->saddr;
				f.dst_ip=ip_header->daddr;
				f.src_port=ntohs(tcp_header->source);
				f.dst_port=ntohs(tcp_header->dest);
				f.i.ack_bytes=ntohl(tcp_header->ack_seq);
				f.i.srtt=MIN_RTT;
				f.i.rwnd=MIN_RWND;
				f.i.phase=0;
				f.i.prio=0;
				f.i.size=0;
				f.i.last_update=get_tsval();
				
				//spin_lock_bh(&globalLock);
				spin_lock_irqsave(&globalLock,flags);
				if(Insert_Table(&ft,&f)==0)
				{
					printk(KERN_INFO "Insert fails\n");
				}
				connections+=1;			//Increasing Connection numbers
				//total_wind+=MIN_RWND;	//Increasing total window size
				
				spin_unlock_irqrestore(&globalLock,flags);
				tcp_modify_outgoing(skb,MIN_RWND);
			}
			else if(tcp_header->fin||tcp_header->rst)
			{
				//If this is FIN packet, an existing Flow record should be removed from Flow table
				f.src_ip=ip_header->saddr;
				f.dst_ip=ip_header->daddr;
				f.src_port=ntohs(tcp_header->source);
				f.dst_port=ntohs(tcp_header->dest);
				Init_Info(&(f.i));
				
				//spin_lock_bh(&globalLock);
				spin_lock_irqsave(&globalLock,flags);
				if(Delete_Table(&ft,&f)==0)
				{
					printk(KERN_INFO "Delete fails\n");
				}
				
				connections-=1;	//Reduce Connection numbers
				//spin_unlock_bh(&globalLock);
				spin_unlock_irqrestore(&globalLock,flags);
				tcp_modify_outgoing(skb,MIN_RWND);
			}
			else
			{
				f.src_ip=ip_header->saddr;
				f.dst_ip=ip_header->daddr;
				f.src_port=ntohs(tcp_header->source);
				f.dst_port=ntohs(tcp_header->dest);
				Init_Info(&(f.i));
				
				//spin_lock_bh(&globalLock);
				//spin_lock_irqsave(&globalLock,flags);
				info_pointer=Search_Table(&ft,&f);
				if(info_pointer==NULL)	
				{
					//spin_unlock_irqrestore(&globalLock,flags);
					printk(KERN_INFO "No this flow record\n");
					tcp_modify_outgoing(skb,MIN_RWND);
				}
				else
				{
					//spin_unlock_irqrestore(&globalLock,flags);
					//Potential time to adjust window
					//In the second subslot 
					//Elapsed time is larger than 2*SRTT of this connection
					if(globalstatus==SECOND_SUBSLOT&&get_tsval()-info_pointer->last_update>=2*info_pointer->srtt)
					{
						info_pointer->last_update=get_tsval();
						
						if(info_pointer->phase==0) //If this flow is in slow start phase
						{
							//tmp=(8*info_pointer->rwnd*1460/MIN_RTT+1)*1000000;
							tmp=(8*info_pointer->rwnd*1460/info_pointer->srtt+1)*1024*1024;
							//printk(KERN_INFO "Slow Start: %lu Mbps VS %lu Mbps\n",capacity/1000000,tmp/1000000); 
							//If there is enough capacity to double window 
							if(capacity>tmp&&connections<10)
							{
								capacity-=tmp;
								//Double window but no larger than MAX_RWND 
								if(2*info_pointer->rwnd>MAX_RWND)
									info_pointer->rwnd=MAX_RWND;
								else
									info_pointer->rwnd=2*info_pointer->rwnd;
								//printk(KERN_INFO "Double window to %u\n",info_pointer->rwnd);
							}
							else //No enough capacity to double window
							{
								//This connection comes into congestion avoidance phase
								info_pointer->phase=1;
								increase=1;
							}
						}
						
						if(info_pointer->phase==1&&increase==0)//If this flow is in congestion avoidance phase
						{
							tmp=(8*1460/info_pointer->srtt+1)*1024*1024;
							//printk(KERN_INFO "Congestion Avoidance: %lu Mbps VS %lu Mbps\n",capacity/1000000,tmp/1000000); 
							//If there is enough capacity to double window 
							if(capacity>tmp&&connections<10)
							{
								capacity-=tmp;
								//Increase window by 1 but no larger than MAX_RWND
								if(info_pointer->rwnd+1>MAX_RWND)
									info_pointer->rwnd=MAX_RWND;
								else
									info_pointer->rwnd+=1;
								//printk(KERN_INFO "Increase window by one to %u\n",info_pointer->rwnd);
							}
						}
					}
					tcp_modify_outgoing(skb,info_pointer->rwnd);
					info_pointer->ack_bytes=ntohl(tcp_header->ack_seq);
				}
				//spin_unlock_bh(&globalLock);
				//spin_unlock_irqrestore(&globalLock,flags);
			}
		}
	}

	return NF_ACCEPT;
}

//PREROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;         //IP  header struct
	struct tcphdr *tcp_header;       //TCP header struct
	unsigned short int src_port;     //TCP source port
	//unsigned short int dst_port;	 //TCP destination port 
	struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int rtt;				 //Sample RTT
	//unsigned long flags;         	 //variable for save current states of irq
	unsigned long throughput=0; 	//Incoming throughput in the latest slot
	unsigned long interval=0;       //Time interval to measure throughput
	
	
	//spin_lock_irqsave(&statisticLock,flags);
	//First, we need to determine whether the interval is larger than avg_RTT
	interval=get_tsval()-last_update;
	if(interval>avg_rtt)
	{
		//Reset last_update
		last_update=get_tsval();
		
		//update statistic information
		if(globalstatus==FIRST_SUBSLOT)
		{
			globalstatus=SECOND_SUBSLOT;
		}
		else
		{
			globalstatus=FIRST_SUBSLOT;
		}
		
		//Calculate aggregate throughput (Mbps)
		throughput=(total_traffic*8*1024/interval+1)*1024;
		//BWa=max(0,0.9C-BWt)
		if(throughput<945000000)
		{
			capacity=945000000-throughput;
		}
		else
		{
			capacity=0;
		}
		//printk(KERN_INFO "Capcity: %lu (Mbps)\n",capacity>>20); 
		//Get new average RTT
		if(samples>0)
		{
			avg_rtt=total_rtt/samples;
			if(avg_rtt<MIN_RTT)
			{
				avg_rtt=MIN_RTT;
			}
		}
		else //No samples in this RTT
		{
			avg_rtt=2*MIN_RTT;  
		}
		//Reset global information
		total_rtt=0;
		samples=0;
		total_traffic=0;
	}
	//spin_unlock_irqrestore(&statisticLock,flags);
	
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
		
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(src_port==5001)
		{
			//Modify incoming packet and get sample RTT value
			rtt=tcp_modify_incoming(skb);
			
			//Search flow information in the table
			//Note that: source and destination should be changed !!!
			f.src_ip=ip_header->daddr;
			f.dst_ip=ip_header->saddr;
			f.src_port=ntohs(tcp_header->dest);
			f.dst_port=ntohs(tcp_header->source);
			Init_Info(&(f.i));
			//spin_lock_irqsave(&globalLock,flags);
			info_pointer=Search_Table(&ft,&f);
			
			//Update information 
			if(info_pointer!=NULL)
			{
				if(rtt!=0)
				{
					//srtt=7/8*srtt+1/8*sample RTT
					info_pointer->srtt=(7*info_pointer->srtt+rtt)/8;
					total_rtt+=rtt;
					samples+=1;
					//printk(KERN_INFO "Sample RTT:%u Smoothed RTT:%u\n",rtt,info_pointer->srtt);
				}
				//update total traffic volume in this RTT	
				total_traffic+=skb->len;	
			}
			//spin_unlock_irqrestore(&globalLock,flags);
		}
	}
	
	return NF_ACCEPT;
}


//Called when module loaded using 'insmod'
int init_module()
{
	//Initialize Lock
	spin_lock_init(&globalLock);
	
	//Initialize Global status and other information
	globalstatus=FIRST_SUBSLOT; 	//First slot is used to measure incoming throughput
	total_rtt=0;					
	samples=0;						
	avg_rtt=MIN_RTT;				
	total_traffic=0;		
	capacity=0;
	last_update=get_tsval();	//Get current time as the latest update time 
	connections=0;
	//total_wind=0;
	
	//Initialize FlowTable
	Init_Table(&ft);
	
	//POSTROUTING
	nfho_outgoing.hook = hook_func_out;                 //function to call when conditions below met
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;       //called in post_routing
	nfho_outgoing.pf = PF_INET;                         //IPV4 packets
	nfho_outgoing.priority = NF_IP_PRI_FIRST;           //set to highest priority over all other hook functions
	nf_register_hook(&nfho_outgoing);                   //register hook*/
        
	//PREROUTING
	nfho_incoming.hook=hook_func_in;					//function to call when conditions below met    
	nfho_incoming.hooknum=NF_INET_PRE_ROUTING;			//called in pre_routing
	nfho_incoming.pf = PF_INET;							//IPV4 packets
	nfho_incoming.priority = NF_IP_PRI_FIRST;			//set to highest priority over all other hook functions
	nf_register_hook(&nfho_incoming);					//register hook*/
	
	
	printk(KERN_INFO "Start ICTCP kernel module\n");

	return 0;
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
	//Unregister two hooks
	nf_unregister_hook(&nfho_outgoing);  
	nf_unregister_hook(&nfho_incoming);
	
	//Clear flow table
	//Print_Table(&ft);
	Empty_Table(&ft);
	
	printk(KERN_INFO "Stop ICTCP kernel module\n");

}
