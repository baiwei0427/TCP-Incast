#ifndef FLOW_H
#define FLOW_H

//Define structure of information for a TCP flow
//srtt: Smoothed Round Trip Time (unit: us)
//phase: TCP phase Slow Start (0) or Congestion Avoidance (1)
//bytes_sent_latest: The (incoming) bytes sent by this flow in the latest interval
//bytes_sent_total: The (incoming) bytes sent by this flow in total 
//last_ack: The latest ACK number of this flow
//last_seq: The latest sequence number of this flow
//last_throughput: The latest incoming throughput of this flow (Mbps)
//last_update: The last update time (unit: us)
//throughput_reduction_num: the number of consecutive intervals of throughput reduction  
struct Info
{
	unsigned int srtt;
	unsigned short int phase;
	unsigned long bytes_sent_latest;
    unsigned long bytes_sent_total;
    unsigned int last_ack;
    unsigned int last_seq;
    unsigned int last_throughput;
    unsigned short int throughput_reduction_num;
	unsigned int last_update;
};

//Define structure of a TCP flow
//Flow is defined by 4-tuple <local_ip,remote_ip,local_port,remote_port> and its related information
struct Flow
{
	unsigned int local_ip;                      //Local IP address
	unsigned int remote_ip;				    //Remote IP address
	unsigned short int local_port;		//Local TCP port
	unsigned short int remote_port;	//Remote TCP port
	struct Info i;											//Information for this flow
};

#endif