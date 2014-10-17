#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

//MSS: 1460 bytes
unsigned int MSS=1460;
//Base RTT: 100 us. This is initial value of srtt of each flow      
unsigned int MIN_RTT=100;
//Minimal Window (MSS) for ICTCP. As authors recommend, it is 2MSS by default.
unsigned int MIN_RWND=2;
//Maximum available bandwidth (Mbps). By default, it is 900Mbps in our 1G testbed.
unsigned int AVAILABLE_BW=900;	
//The bandwidth threshold for fairness control (Mbps). By default, it is 200Mbps in our 1G testbed.
unsigned int SPARE_BW=200;

//parameter to smooth measured throughput. beta/1000 is actually smooth parameter in (0,1)  
unsigned int Beta=200; 			                     
//gamma1 for ICTCP congestion control. gamma1/1000  
unsigned int Gamma1=100;
//gamma2 for ICTCP congestion control. gamma2/1000  
unsigned int Gamma2=500;

//parameter to smooth RTT: srtt=rtt_smooth/1000*srtt+(1000-rtt_smooth)/1000*rtt
unsigned int RTT_SMOOTH=875;

//ICTCP only controls flows whose RTTs are smaller than <max_rtt>. By default, it is 2ms(2000us) as authors recommend.
//unsigned int MAX_RTT=2000;

#endif 