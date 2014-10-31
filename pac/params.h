#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

//MSS: 1460 bytes
static unsigned int MSS=1460;
//TCP Initial Window (3MSS by default)
static unsigned int MIN_WIN=3;
//Timer interval
static unsigned long DELAY_IN_US=100L;
//Base RTT: 200 us
static unsigned int MIN_RTT=200;
//Switch buffer size. By default, it is 80KB (4MB/48 ports) in our testbed
static unsigned int BUFFER_SIZE=80*1024;
//Minimal TCP packet length (Ethernet header 14+IP header 20+TCP header 20+TCP option 20=74)
static unsigned int MIN_PKT_LEN=74;

//parameter to smooth incoming throughput: sthroughput=throughput_smooth/1000*sthroughput+(1000-throughput_smooth)/1000*throughput in the interval 
static unsigned int THROUGHPUT_SMOOTH=200;
//parameter to smooth RTT: srtt=rtt_smooth/1000*srtt+(1000-rtt_smooth)/1000*rtt
static unsigned int RTT_SMOOTH=875;
//parameter to determine throughput reduction (alpha/1000)
static unsigned int ALPHA=800;

#endif 