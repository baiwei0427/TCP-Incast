#ifndef FLOW_H
#define FLOW_H

//Define structure of information for a TCP flow
//srtt: Smoothed Round Trip Time (unit: us)
//rwnd: Receive Window (unit: maximum segment size)
//scale: Window scaling 
//phase: TCP phase Slow Start (0) or Congestion Avoidance (1)
//size: The total amount of traffic in the latest control interval (unit: bytes)
//throughput: The sample of throughput in the latest control interval (unit: bps)
//last_update: Last update time (unit: us)

struct Info{

	unsigned int srtt;
	unsigned int rwnd;
	unsigned int scale;
	unsigned short int phase;
	unsigned long size;
	unsigned long throughput;
	unsigned int last_update;
	
};

//Define structure of a TCP flow
//Flow is defined by 4-tuple <local_ip,remote_ip,local_port,remote_port> and its related information
struct Flow{

	unsigned int local_ip;                      //Local IP address
	unsigned int remote_ip;				    //Remote IP address
	unsigned short int local_port;		//Local TCP port
	unsigned short int remote_port;	//Remote TCP port
	struct Info i;											//Information for this flow
	
};

#endif