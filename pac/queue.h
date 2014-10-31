#ifndef QUEUE_H
#define QUEUE_H

#include <linux/vmalloc.h>

#define MAX_QUEUE_LEN 2048

struct Packet
{
    int (*okfn)(struct sk_buff *); //function pointer to reinject packets
    struct sk_buff *skb;                 //socket buffer pointer to packet   
    unsigned int trigger;               //The size of traffic that this ACK packet can trigger
}; 

struct PacketQueue
{
    struct Packet *packets; //Array of packets
    unsigned int head;         //Head offset
	unsigned int size;            //Current queue length
};

static void Init_PacketQueue(struct PacketQueue* q)
{
	q->packets=vmalloc(MAX_QUEUE_LEN*sizeof(struct Packet));
	q->head=0;
	q->size=0;
}

static void Free_PacketQueue(struct PacketQueue* q)
{
	vfree(q->packets);
}

static int Enqueue_PacketQueue(struct PacketQueue* q,struct sk_buff *skb,int (*okfn)(struct sk_buff *), unsigned int trigger)
{
	//There is capacity to contain new packets
	if(q->size<MAX_QUEUE_LEN) 
    {
		//Index for new insert packet
		int queueIndex=(q->head+q->size)%MAX_QUEUE_LEN;
		q->packets[queueIndex].skb=skb;
		q->packets[queueIndex].okfn=okfn;
        q->packets[queueIndex].trigger=trigger;
		q->size++;
		return 1;
	} 
    else
    {
		return 0;
	}
}

static int Dequeue_PacketQueue(struct PacketQueue* q)
{
	if(q->size>0) 
    {
		q->size--;
		//Dequeue packet
		(q->packets[q->head].okfn)(q->packets[q->head].skb);
		//Reinject head packet of current queue
		q->head=(q->head+1)%MAX_QUEUE_LEN;
		return 1;
	} 
    else 
    {
		return 0;
	}
}

#endif
