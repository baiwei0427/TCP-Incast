#ifndef QUEUE_H
#define QUEUE_H

#include <linux/vmalloc.h>

#define MAX_QUEUE_LEN 4096

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
    spinlock_t queue_lock;//Lock for the PacketQueue
};

static void Init_PacketQueue(struct PacketQueue* q)
{
	q->packets=vmalloc(MAX_QUEUE_LEN*sizeof(struct Packet));
	q->head=0;
	q->size=0;
	spin_lock_init(&q->queue_lock);
}

static void Free_PacketQueue(struct PacketQueue* q)
{
	vfree(q->packets);
}

static int Enqueue_PacketQueue(struct PacketQueue* q,struct sk_buff *skb,int (*okfn)(struct sk_buff *), unsigned int trigger)
{
    unsigned long flags;                     //variable for save current states of irq
	//There is capacity to contain new packets
	if(q->size<MAX_QUEUE_LEN) 
    {
        spin_lock_irqsave(&(q->queue_lock),flags);
		//Index for new insert packet
		int queueIndex=(q->head+q->size)%MAX_QUEUE_LEN;
		q->packets[queueIndex].skb=skb;
		q->packets[queueIndex].okfn=okfn;
        q->packets[queueIndex].trigger=trigger;
		q->size++;
        spin_unlock_irqrestore(&(q->queue_lock),flags);
		return 1;
	} 
    else
    {
		return 0;
	}
}

static int Dequeue_PacketQueue(struct PacketQueue* q)
{
    unsigned long flags;                     //variable for save current states of irq
	if(q->size>0) 
    {
        spin_lock_irqsave(&(q->queue_lock),flags);
		q->size--;
		//Dequeue packet
		(q->packets[q->head].okfn)(q->packets[q->head].skb);
		//Reinject head packet of current queue
		q->head=(q->head+1)%MAX_QUEUE_LEN;
        spin_unlock_irqrestore(&(q->queue_lock),flags);
		return 1;
	} 
    else 
    {
		return 0;
	}
}

#endif
