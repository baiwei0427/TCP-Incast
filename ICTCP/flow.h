#ifndef FLOW_H
#define FLOW_H

//Define structure of information for a TCP flow
//ack_bytes: Latest Acknowledgement Sequence Number
//srtt: Smoothed Round Trip Time (us)
//rwnd: Receive Window (MSS)
//phase: TCP phase Slow Start (1) or Congestion Avoidance (0)
//prio: Priority of this flow High (1) or Low (0) 

//The structure of Info is very important for both PAC and ICTCP
//ICTCP requires srtt and rwnd
//PAC requires ack_bytes, phase and prio 
struct Info{

	unsigned int ack_bytes;
	unsigned short srtt;
	unsigned short rwnd;
	unsigned short phase;
	unsigned short prio;
	
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