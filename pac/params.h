#ifndef __PARAMS_H__
#define __PARAMS_H__

#include <linux/types.h>

//MSS: 1460 bytes
unsigned int MSS=1460;
//Base RTT: 200 us
unsigned int MIN_RTT=200;
//Switch buffer size. By default, it is 80KB (4MB/48 ports) in our testbed
unsigned int BUFFER_SIZE=80*1024£»
//Minimal TCP packet length
unsigned int MIN_PKT_LEN=74;

#endif 