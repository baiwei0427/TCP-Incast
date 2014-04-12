#ifndef FLOW_H
#define FLOW_H

//Define structure of information for a TCP flow
//ack_bytes: Latest Acknowledgement Sequence Number
//srtt: Smoothed Round Trip Time (us)
//rwnd: Receive Window (MSS)
//phase: TCP phase Slow Start (0) or Congestion Avoidance (1)
//prio: Priority of this flow High (0) or Low (1) 
//size: The total amount of traffic in the latest RTT
//last_update: Last update time (us)

//The structure of Info is very important for both PAC and ICTCP
//ICTCP requires srtt, rwnd, size and last_update
//PAC requires ack_bytes, phase and prio 
struct Info{

	unsigned int ack_bytes;
	unsigned short srtt;
	unsigned short rwnd;
	unsigned short phase;
	unsigned short prio;
	unsigned int size;
	unsigned int last_update;
	
};

//Define structure of a TCP flow
//Flow is defined by as 4-tuple <src_ip,dst_ip,src_port,dst_port> and its related information
struct Flow{

	unsigned int src_ip; 		//Local IP address
	unsigned int dst_ip; 		//Remote IP address
	unsigned short src_port;	//Local TCP port
	unsigned short dst_port;	//Remote TCP port
	struct Info i;				//Information for this flow
	
};

#endif