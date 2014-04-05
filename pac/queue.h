#ifndef QUEUE_H
#define QUEUE_H

#include <linux/vmalloc.h>

#define QUEUE_SIZE 2048
#define ECN_THRESHOLD 30000 //(bytes)

struct Packet{

    int (*okfn)(struct sk_buff *);  //function pointer to reinject packets
    struct sk_buff *skb;           //socket buffer pointer to packet               
}; 

struct PacketQueue{
    struct Packet *packets;
    int head;
	int size;
	int bytes;
};

static void Init_PacketQueue(struct PacketQueue* q)
{
	q->packets=vmalloc(QUEUE_SIZE*sizeof(struct Packet));
	q->head=0;
	q->size=0;
	q->bytes=0;
}

static void Free_PacketQueue(struct PacketQueue* q)
{
	vfree(q->packets);
}

static int Enqueue_PacketQueue(struct PacketQueue* q,struct sk_buff *skb,int (*okfn)(struct sk_buff *))
{
	//There is capacity to contain new packets
	if(q->size<QUEUE_SIZE) {

		//Index for new insert packet
		int queueIndex=(q->head+q->size)%QUEUE_SIZE;
		q->packets[queueIndex].skb=skb;
		q->packets[queueIndex].okfn=okfn;
		q->size++;
		q->bytes+=skb->len;
		return 1;

	} else {

		return 0;
	}
}

static int Dequeue_PacketQueue(struct PacketQueue* q)
{
	if(q->size>0) {
		//Dequeue Marking
		if(q->bytes>ECN_THRESHOLD)
		{
			struct iphdr *ip_header=(struct iphdr *)skb_network_header(q->packets[q->head].skb);
			//Marking ECN
			ip_header->tos+=0x01;
			//Calculate IP header checksum
			ip_header->check=0;
			ip_header->check=ip_fast_csum(ip_header,ip_header->ihl);		
		}
		q->bytes-=q->packets[q->head].skb->len;
		q->size--;
		//Dequeue packet
		(q->packets[q->head].okfn)(q->packets[q->head].skb);
		//Reinject head packet of current queue
		q->head=(q->head+1)%QUEUE_SIZE;
		return 1;

	} else {
	
		return 0;
	}

}

#endif
