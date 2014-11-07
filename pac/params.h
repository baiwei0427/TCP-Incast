#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

//microsecond to nanosecond
#define US_TO_NS(x)	(x * 1E3L)
//millisecond to nanosecond
#define MS_TO_NS(x)	(x * 1E6L)
//Slow start
#define SLOW_START 0
//Congestion avoidance
#define CONGESTION_AVOIDANCE 1
//High priority 
#define HIGH_PRIORITY 0
//Low priority
#define LOW_PRIORITY 1

//MSS: 1460 bytes
static unsigned int MSS=1460;
//TCP Initial Window (3MSS by default)
static unsigned int MIN_WIN=3;
//Timer interval
static unsigned long DELAY_IN_US=50L;
//Base RTT: 200 us
static unsigned int MIN_RTT=200;
//Maximum RTT: 1ms
static unsigned int MAX_RTT=1000;
//Maximum delay added by PAC in the absence of short flows: 10ms
static unsigned int MAX_DELAY=10000;
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
//Per-flow throughput reduction threshold
static unsigned short int REDUCTION_THRESH=3;

//priority threshold (bytes). It is 1MB by default in our experiments
static unsigned long PRIO_THRESH=1024*1024;
//Slow start threshold
static unsigned long SS_THRESH=1024*1024;

#endif 