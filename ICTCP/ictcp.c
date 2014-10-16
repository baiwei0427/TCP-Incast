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
#include "network_func.h"

//Default parameters
#define MSS 1460								//MSS: 1460 bytes
#define MIN_RTT 100						//Base RTT: 100 us. This is initial value of srtt of each flow
#define MIN_RWND 2						//Minimal Window: 2MSS for ICTCP
#define MAX_RWND 40					//Maximum Window: 40MSS 
#define AVAILABLE_BW 940			//Maximum Available Bandwidth: 940Mbps
#define FIRST_SUBSLOT 0				//Status in first subslot
#define SECOND_SUBSLOT 1 		//Status in second subslot
#define US_TO_NS(x)	(x * 1E3L)  //microsecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)  //millisecond to nanosecond

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.1");
MODULE_DESCRIPTION("Kernel module in Linux for ICTCP");

//Glbal update time
static unsigned int last_update;
//Global Lock (For table)
static spinlock_t globalLock;
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
static unsigned int total_wind;
//Total concurrent connection numbers
static unsigned int connections;
//Average window
static unsigned int avg_wind; 

//Outgoing packets POSTROUTING
static struct nf_hook_ops nfho_outgoing;
//Incoming packets PREROUTING
static struct nf_hook_ops nfho_incoming;

//POSTROUTING for outgoing packets
//We implement ICTCP congestion control algorithm in this function
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         	//IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	unsigned short int dst_port;     	  		//TCP destination port
	unsigned short int src_port;	 	  			//TCP source port
	struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int expected_throughput;	//expected throughput
	//unsigned short reduce=0;	 					//whether the window has been reduced due to fairness problem
	unsigned long flags;         	 					//variable for save current states of irq
	unsigned long tmp=0;
	//unsigned short increase=0;		 		//Whether this flow's rwnd has been increased
	
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
		src_port=htons((unsigned short int) tcp_header->source);
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(dst_port==5001||src_port==5001)
		{
			//If this is SYN packet, a new Flow record should be inserted into Flow table
			if(tcp_header->syn)
			{
				f.local_ip=ip_header->saddr;
				f.remote_ip=ip_header->daddr;
				f.local_port=ntohs(tcp_header->source);
				f.remote_port=ntohs(tcp_header->dest);
				f.i.srtt=MIN_RTT;
				f.i.rwnd=MIN_RWND;
				f.i.scale=tcp_get_scale(skb);
				f.i.phase=0;
				f.i.size=0;
				f.i.throughput=0;
				f.i.last_update=get_tsval();
				
				//spin_lock_bh(&globalLock);
				spin_lock_irqsave(&globalLock,flags);
				if(Insert_Table(&ft,&f)==0)
				{
					printk(KERN_INFO "Insert fails\n");
				}
				connections+=1;						//Increase connection numbers
				total_wind+=MIN_RWND;	//Increase total window size
				avg_wind=total_wind/connections;	//Calculate average window size 
				
				spin_unlock_irqrestore(&globalLock,flags);
				tcp_modify_outgoing(skb,MIN_RWND*MSS, get_tsval());
			}
			//If this is FIN packet, an existing Flow record should be removed from Flow table
			else if(tcp_header->fin||tcp_header->rst)
			{
				f.local_ip=ip_header->saddr;
				f.remote_ip=ip_header->daddr;
				f.local_port=ntohs(tcp_header->source);
				f.remote_port=ntohs(tcp_header->dest);
				Init_Info(&(f.i));
						
				spin_lock_irqsave(&globalLock,flags);
				tmp=Delete_Table(&ft,&f);
				if(tmp==0)
				{
					printk(KERN_INFO "Delete fails\n");
				}	
				else
				{
					connections-=1;			//Reduce connection numbers
					total_wind-=tmp;		//Reduce total window size
					if(connections>0)
						avg_wind=total_wind/connections;
					else
						avg_wind=0;	
				}
				spin_unlock_irqrestore(&globalLock,flags);
				tcp_modify_outgoing(skb,MIN_RWND*MSS, get_tsval());
			}
			else
			{
				f.local_ip=ip_header->saddr;
				f.remote_ip=ip_header->daddr;
				f.local_port=ntohs(tcp_header->source);
				f.remote_port=ntohs(tcp_header->dest);
				Init_Info(&(f.i));
				
				info_pointer=Search_Table(&ft,&f);
				if(info_pointer==NULL)	
				{
					printk(KERN_INFO "No this flow record\n");
					tcp_modify_outgoing(skb,MIN_RWND*MSS, get_tsval());
				}
				//ICTCP congestion control algorithm 
				else
				{					
					//The control interval is larger than 2*SRTT of this connection. That is potential time to adjust window
					if(get_tsval()-info_pointer->last_update>=2*info_pointer->srtt)
					{
						//Update per-flow information (e.g. measured throughput )
						spin_lock_irqsave(&globalLock,flags);
						info_pointer->last_update=get_tsval();
						//Smooth measured throughput in the latest control interval
						info_pointer->throughput=max(info_pointer->size*8*1024/info_pointer->srtt*1024,(4*info_pointer->size*8*1024/info_pointer->srtt*1024+info_pointer->throughput)/5);
						//Clear traffic size 
						info_pointer->size=0;
						//Calculate expected throughput for this flow 
						expected_throughput=max((info_pointer->rwnd*MSS*8*1024/info_pointer->srtt*1024),info_pointer->throughput);
						spin_unlock_irqrestore(&globalLock,flags);	
							
						//Fairness control 
						if(capacity<200*1024*1024 && info_pointer->rwnd>avg_wind && info_pointer->rwnd>MIN_RWND)
						{
							spin_lock_irqsave(&globalLock,flags);
							//Reduce window by 1MSS
							info_pointer->rwnd-=1;
							total_wind-=1;
							capacity+=8*MSS*1024/info_pointer->srtt*1024;
							if(connections>0)
							{
								avg_wind=total_wind/connections;
							}
							else
							{
								avg_wind=0;
							}
							spin_unlock_irqrestore(&globalLock,flags);	
							printk(KERN_INFO "There are %u connections. Their total window size is %u MSS\n",connections,total_wind);
							printk(KERN_INFO "Reduce window to %u for fairness\n",info_pointer->rwnd);
							
						}
						//Application demand control						
						else    
						{							
							//The window should be increased 
							if((expected_throughput-info_pointer->throughput<=expected_throughput/10 || expected_throughput-info_pointer->throughput<=expected_throughput/info_pointer->rwnd)&&globalstatus==SECOND_SUBSLOT)
							{
								//Slow start
								if(info_pointer->phase==0) 
								{
									tmp=(8*info_pointer->rwnd*MSS/info_pointer->srtt+1)*1024*1024;
									//If there is enough capacity to double window 
									if(capacity>tmp)
									{
										spin_lock_irqsave(&globalLock,flags);
										capacity-=tmp;
										total_wind+=info_pointer->rwnd;
										if(connections>0)
										{
											avg_wind=total_wind/connections;
										}
										else
										{
											avg_wind=0;
										}
										info_pointer->rwnd=2*info_pointer->rwnd;
										spin_unlock_irqrestore(&globalLock,flags);
									}
									else //No enough capacity to double window
									{
										//This connection comes into congestion avoidance phase
										spin_lock_irqsave(&globalLock,flags);
										info_pointer->phase=1;
										spin_unlock_irqrestore(&globalLock,flags);
									}
								}
								//Congestion avoidance
								else
								{
									tmp=(8*MSS/info_pointer->srtt+1)*1024*1024;
									//If there is enough capacity to double window 
									if(capacity>tmp)
									{
										spin_lock_irqsave(&globalLock,flags);
										capacity-=tmp;
										total_wind+=1;
										if(connections>0)
										{
											avg_wind=total_wind/connections;
										}
										else
										{
											avg_wind=0;
										}
										info_pointer->rwnd+=1;
										spin_unlock_irqrestore(&globalLock,flags);
									}
								}
							}
							//The window should be decreased
							else if(expected_throughput-info_pointer->throughput>=expected_throughput/2 && info_pointer->rwnd>MIN_RWND)
							{
								spin_lock_irqsave(&globalLock,flags);
								total_wind-=1;
								if(connections>0)
								{
									avg_wind=total_wind/connections;
								}
								else
								{
									avg_wind=0;
								}
								info_pointer->rwnd-=1;
								spin_unlock_irqrestore(&globalLock,flags);
								printk(KERN_INFO "Reduce window to %u to meet application demand\n",info_pointer->rwnd);
							}
						}
					}
					tcp_modify_outgoing(skb,(info_pointer->rwnd*MSS+MSS/2)/pow(info_pointer->scale), get_tsval());
				}
			}
		}
	}
	return NF_ACCEPT;
}

//PREROUTING for incoming packets
static unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header;         	//IP  header struct
	struct tcphdr *tcp_header;    	//TCP header struct
	unsigned short int src_port;		//TCP source port
	unsigned short int dst_port;		//TCP destination port 
	struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int rtt;				 				//Sample RTT
	unsigned long flags;         	 		//variable for save current states of irq
	unsigned long throughput=0; 	//Incoming throughput in the latest slot
	unsigned long interval=0;       	//Time interval to measure throughput
		
	//First, we need to determine whether the interval is larger than avg_RTT.
	//If the interval is large enough, we need to update some global information
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
		throughput=total_traffic*8*1024*1024/interval;
		//BWa=max(0,0.9C-BWt)
		if(throughput<AVAILABLE_BW*1024*1024)
		{
			capacity=AVAILABLE_BW*1024*1024-throughput;
		}
		else
		{
			capacity=0;
		}
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
	
	total_traffic+=skb->len;	
	
	//Then, we need to update per-flow information based on incoming packets
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
		//Get destination TCP port 
		dst_port=htons((unsigned short int) tcp_header->dest);
		
		//We only use ICTCP to control incast traffic (tcp port 5001)
		if(src_port==5001||dst_port==5001)
		{
			//Modify incoming packet and get sample RTT value
			rtt=tcp_modify_incoming(skb);
			
			//Search flow information in the table
			//Note that: source and destination should be changed !!!
			f.local_ip=ip_header->daddr;
			f.remote_ip=ip_header->saddr;
			f.local_port=ntohs(tcp_header->dest);
			f.remote_port=ntohs(tcp_header->source);
			Init_Info(&(f.i));
			
			info_pointer=Search_Table(&ft,&f);
			if(info_pointer!=NULL)
			{
				if(rtt!=0)
				{
					spin_lock_irqsave(&globalLock,flags);
					//Update RTT: srtt=7/8*srtt+1/8*sample RTT
					info_pointer->srtt=(7*info_pointer->srtt+rtt)/8;
					//Update incoming flow size
					info_pointer->size+=skb->len;
					total_rtt+=rtt;
					samples+=1;
					spin_unlock_irqrestore(&globalLock,flags);
					//printk(KERN_INFO "Sample RTT:%u Smoothed RTT:%u\n",rtt,info_pointer->srtt);
				}
			}
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
	//First slot is used to measure incoming throughput
	globalstatus=FIRST_SUBSLOT; 
	total_rtt=0;					
	samples=0;						
	avg_rtt=MIN_RTT;				
	total_traffic=0;		
	capacity=0;
	//Get current time as the latest update time 
	last_update=get_tsval();	
	connections=0;
	total_wind=0;
	avg_wind=0;
	
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

