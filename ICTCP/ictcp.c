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
#include "params.h"
#include "network_func.h"

//Status in first subslot
#define FIRST_SUBSLOT 0		
//Status in second subslot		
#define SECOND_SUBSLOT 1 	
//Slow start
#define SLOW_START 0
//Congestion avoidance
#define CONGESTION_AVOIDANCE 1

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BAI Wei baiwei0427@gmail.com");
MODULE_VERSION("1.1");
MODULE_DESCRIPTION("Linux kernel module for ICTCP");

char *param_dev=NULL;
MODULE_PARM_DESC(param_dev, "Interface to operate ICTCP");
module_param(param_dev, charp, 0);


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
static unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	struct iphdr *ip_header=NULL;         	//IP  header structure
	struct tcphdr *tcp_header=NULL;       //TCP header structure
	struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int expected_throughput;	//expected throughput
	unsigned long flags;         	 					//variable for save current states of irq
	unsigned long tmp=0;
	
    if(!out)
        return NF_ACCEPT;
        
    if(strcmp(out->name,param_dev)!=0)
        return NF_ACCEPT;
     
	ip_header=(struct iphdr *)skb_network_header(skb);

	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
		return NF_ACCEPT;

	if(ip_header->protocol==IPPROTO_TCP) //TCP
	{
		tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
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
				
			spin_lock_irqsave(&globalLock,flags);
			if(Insert_Table(&ft,&f)==0)
				printk(KERN_INFO "Insert fails\n");
			connections+=1;						//Increase connection numbers
			total_wind+=MIN_RWND;	//Increase total window size
			avg_wind=total_wind/connections;	//Calculate average window size 
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
			/*if(info_pointer==NULL)	
			{
				printk(KERN_INFO "No this flow record\n");
				tcp_modify_outgoing(skb,MIN_RWND*MSS, get_tsval());
			}*/
			//ICTCP congestion control algorithm 
			if(info_pointer!=NULL)
			{					
				//The control interval is larger than 2*SRTT of this connection. That is potential time to adjust window
				if(get_tsval()-info_pointer->last_update>=2*info_pointer->srtt)
				{
					//Update per-flow information (e.g. measured throughput )
					spin_lock_irqsave(&globalLock,flags);
					info_pointer->last_update=get_tsval();
					//Smooth measured throughput in the latest control interval
					info_pointer->throughput=max(info_pointer->size*8*1024/info_pointer->srtt*1024,(Beta*info_pointer->throughput+(1000-Beta)*info_pointer->size*8*1024/info_pointer->srtt*1024)/1000);
					//Clear traffic size 
					info_pointer->size=0;
					//Calculate expected throughput for this flow 
					expected_throughput=max((info_pointer->rwnd*MSS*8*1024/info_pointer->srtt*1024),info_pointer->throughput);
					spin_unlock_irqrestore(&globalLock,flags);	
						
					//Fairness control 
					if(capacity<SPARE_BW*1024*1024 && info_pointer->rwnd>avg_wind && info_pointer->rwnd>MIN_RWND)
					{
						spin_lock_irqsave(&globalLock,flags);
						//Reduce window by 1MSS
						info_pointer->rwnd-=1;
						total_wind-=1;
						capacity+=8*MSS*1024/info_pointer->srtt*1024;
						if(connections>0)
							avg_wind=total_wind/connections;
						else
                            avg_wind=0;
						spin_unlock_irqrestore(&globalLock,flags);	
						printk(KERN_INFO "There are %u connections. Their total window size is %u MSS\n",connections,total_wind);
						printk(KERN_INFO "Reduce window to %u for fairness\n",info_pointer->rwnd);		
					}
					//Application demand control						
					else    
					{							
						//The window should be increased 
						if((expected_throughput-info_pointer->throughput<=expected_throughput*Gamma1/1000 || expected_throughput-info_pointer->throughput<=expected_throughput/info_pointer->rwnd)&&globalstatus==SECOND_SUBSLOT)
						{
							//Slow start
							if(info_pointer->phase==SLOW_START) 
							{
									tmp=(8*info_pointer->rwnd*MSS/info_pointer->srtt+1)*1024*1024;
									//If there is enough capacity to double window 
									if(capacity>tmp)
									{
										spin_lock_irqsave(&globalLock,flags);
										capacity-=tmp;
										total_wind+=info_pointer->rwnd;
										if(connections>0)
											avg_wind=total_wind/connections;
										else
											avg_wind=0;
										info_pointer->rwnd=2*info_pointer->rwnd;
										spin_unlock_irqrestore(&globalLock,flags);
									}
									else //No enough capacity to double window
									{
										//This connection comes into congestion avoidance phase
										spin_lock_irqsave(&globalLock,flags);
										info_pointer->phase=CONGESTION_AVOIDANCE;
										spin_unlock_irqrestore(&globalLock,flags);
									}
							}
							//Congestion avoidance
							if(info_pointer->phase==CONGESTION_AVOIDANCE)
							{
								tmp=(8*MSS/info_pointer->srtt+1)*1024*1024;
								//If there is enough capacity to increase window by one MSS
								if(capacity>tmp)
								{
									spin_lock_irqsave(&globalLock,flags);
									capacity-=tmp;
									total_wind+=1;
                                    if(connections>0)
										avg_wind=total_wind/connections;
									else
										avg_wind=0;
									info_pointer->rwnd+=1;
									spin_unlock_irqrestore(&globalLock,flags);
								}
							}
						}
						//The window should be decreased
						else if(expected_throughput-info_pointer->throughput>=expected_throughput*Gamma2/1000 && info_pointer->rwnd>MIN_RWND)
						{
							spin_lock_irqsave(&globalLock,flags);
							total_wind-=1;
							if(connections>0)
								avg_wind=total_wind/connections;
							else
								avg_wind=0;
							info_pointer->rwnd-=1;
							spin_unlock_irqrestore(&globalLock,flags);
							printk(KERN_INFO "Reduce window to %u to meet application demand\n",info_pointer->rwnd);
						}
					}
				}
                tcp_modify_outgoing(skb,info_pointer->rwnd*MSS/pow(info_pointer->scale)+1, get_tsval());
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
	struct Flow f;
	struct Info* info_pointer=NULL;
	unsigned int rtt;				 				//Sample RTT
    unsigned int tmp;
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
			globalstatus=SECOND_SUBSLOT;
		else
			globalstatus=FIRST_SUBSLOT;
		
		//Calculate aggregate throughput (Mbps)
		throughput=total_traffic*8*1024*1024/interval;
		//BWa=max(0,0.9C-BWt)
		if(throughput<AVAILABLE_BW*1024*1024)
			capacity=AVAILABLE_BW*1024*1024-throughput;
		else
			capacity=0;
            
		//Get new average RTT
		if(samples>0)
		{
			avg_rtt=total_rtt/samples;
			if(avg_rtt<MIN_RTT)
				avg_rtt=MIN_RTT;
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
    //Then, we need to update per-flow information based on incoming packets
    if(!in)
        return NF_ACCEPT;
    
    if(strcmp(in->name,param_dev)!=0)
        return NF_ACCEPT;
	
    total_traffic+=skb->len;	
	ip_header=(struct iphdr *)skb_network_header(skb);
	//The packet is not ip packet (e.g. ARP or others)
	if (!ip_header)
		return NF_ACCEPT;
	
	if(ip_header->protocol==IPPROTO_TCP) //TCP
	{
        tcp_header = (struct tcphdr *)((__u32 *)ip_header+ ip_header->ihl);
        //Note that: source and destination should be changed !!!
        f.local_ip=ip_header->daddr;
        f.remote_ip=ip_header->saddr;
        f.local_port=ntohs(tcp_header->dest);
        f.remote_port=ntohs(tcp_header->source);
        Init_Info(&(f.i));
        
        //Delete flow entry when we observe FIN or RST packets 
        if(tcp_header->fin||tcp_header->rst)
        {						
			spin_lock_irqsave(&globalLock,flags);
			tmp=Delete_Table(&ft,&f);
			//if(tmp==0)
			//	printk(KERN_INFO "Delete fails\n");
			if(tmp!=0)
			{
				connections-=1;			//Reduce connection numbers
				total_wind-=tmp;		//Reduce total window size
				if(connections>0)
					avg_wind=total_wind/connections;
				else
					avg_wind=0;	
			}
			spin_unlock_irqrestore(&globalLock,flags);
		}
        //Update per-flow information
		else
        {   //Modify incoming packet and get sample RTT value
            rtt=tcp_modify_incoming(skb);
            //Search flow information in the table
            info_pointer=Search_Table(&ft,&f);
            if(info_pointer!=NULL)
            {
                if(rtt!=0)
                {
                    spin_lock_irqsave(&globalLock,flags);
                    //Get smooth RTT
					info_pointer->srtt=(RTT_SMOOTH*info_pointer->srtt+(1000-RTT_SMOOTH)*rtt)/1000;
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
    int i=0;
    //Get interface
    if(param_dev==NULL) 
    {
        printk(KERN_INFO "ictcp: not specify network interface.\n");
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
	
	//POSTROUTING Hook
	nfho_outgoing.hook = hook_func_out;                                    
	nfho_outgoing.hooknum = NF_INET_POST_ROUTING;       
	nfho_outgoing.pf = PF_INET;                                                       
	nfho_outgoing.priority = NF_IP_PRI_FIRST;                            
	nf_register_hook(&nfho_outgoing);                                         
        
	//PREROUTING Hook
	nfho_incoming.hook=hook_func_in;					                  
	nfho_incoming.hooknum=NF_INET_PRE_ROUTING;			
	nfho_incoming.pf = PF_INET;							                          
	nfho_incoming.priority = NF_IP_PRI_FIRST;			              
	nf_register_hook(&nfho_incoming);					                     
	
	
	printk(KERN_INFO "Start ICTCP kernel module on %s\n", param_dev);

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

