/* -*-	Mode:C++; c-basic-offset:8; tab-width:8; indent-tabs-mode:t -*- */
/*
 * Copyright (c) Xerox Corporation 1997. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * Linking this file statically or dynamically with other modules is making
 * a combined work based on this file.  Thus, the terms and conditions of
 * the GNU General Public License cover the whole combination.
 *
 * In addition, as a special exception, the copyright holders of this file
 * give you permission to combine this file with free software programs or
 * libraries that are released under the GNU LGPL and with code included in
 * the standard release of ns-2 under the Apache 2.0 license or under
 * otherwise-compatible licenses with advertising requirements (or modified
 * versions of such code, with unchanged license).  You may copy and
 * distribute such a system following the terms of the GNU GPL for this
 * file and the licenses of the other code concerned, provided that you
 * include the source code of that other code when and as the GNU GPL
 * requires distribution of source code.
 *
 * Note that people who make modified versions of this file are not
 * obligated to grant this special exception for their modified versions;
 * it is their choice whether to do so.  The GNU General Public License
 * gives permission to release a modified version without this exception;
 * this exception also makes it possible to release a modified version
 * which carries forward this exception.
 */

/* Shaper which has following 6 parameters :
 * 1.rate_: Bottleneck link bandwidth
 * 2.bucket_: Bucket depth, equal to available switch buffer size
 * 3.thresh_: Max threshold of on the flying TCP traffic. 
 * 4.delack_: Whether TCP uses TCPSink/DelAck.
 * 5.qlen_: Length of packet queue to buffer packets
 * 6.senders_£ºNumber of flows(senders)
 * 7.queue_thresh_: Threshold to drop ACK packets to decrease RTT
 */

#include "connector.h" 
#include "packet.h"
#include "queue.h"
#include "shaper.h"
#include <tcp.h>

SHAPER::SHAPER() :tokens_(0),shaper_timer_(this), init_(1)
{
	//q_=new PacketQueue();
	bind_bw("rate_",&rate_);
	bind("bucket_",&bucket_);
	bind("thresh_",&thresh_);
	bind("qlen_",&qlen_);
	bind("delack_",&delack_);
	bind("senders_",&senders_);
	bind("queue_thresh_",&queue_thresh_);

}

SHAPER::~SHAPER()
{
	int i=0;
	for(i=0;i<senders_;i++)
	{
		if (q_[i]->length()!=0)
		{
			//Clear all pending timers
			shaper_timer_.cancel();
			//Free up the packetqueue
			for (Packet *p=q_[i]->head();p!=0;p=p->next_) 
				Packet::free(p);

		}
		delete q_[i];
	}
	delete[] q_;
	//Clear all flow states
	delete[] flows_;
}

/*
double SHAPER::getupdatedtokens(void)
{
	double now=Scheduler::instance().clock();
	
	tokens_ -= (now-lastupdatetime_)*rate_;
	if (tokens_ < 0)
		tokens_=0;
	lastupdatetime_ = now;
	fprintf(stderr,"%f %d\r\n",now,(int)(tokens_*1500/MTU));
	return tokens_;
}*/

//Identify a flow coming into CA phase
/*
void SHAPER::identify(int k)
{
	flows_[k]=1;
}*/

//Reset on the flying TCP traffic to a value
void SHAPER::reset(double k)
{
	double now=Scheduler::instance().clock();
	if(k>=0) 
	{
		tokens_=k*thresh_/1500*MTU;
	}	
	else 
	{
		tokens_=0;
	}
	//lastupdatetime_ = now;
	fprintf(stderr,"%f %d Reset\r\n",now,(int)(tokens_/MTU*1500));
}

void SHAPER::recv(Packet *p, Handler *)
{
	//Initialize flow states and packet queues
	//Start with no on the flying TCP traffic
	if (init_) {
		flows_=new int[senders_];

		//All flows are not initialized
		int i=0;
		for(i=0;i<senders_;i++)
		{
			flows_[i]=0;
		}

		//Initialize flow packet queues
		q_=new PacketQueue*[senders_];
		for(i=0;i<senders_;i++)
		{
			q_[i]=new PacketQueue();
		}
		//No on the flying TCP traffic
		tokens_=0;
		//lastupdatetime_ = Scheduler::instance().clock();
		init_=0;
		iteration=0;

		hdr_cmn *ch=hdr_cmn::access(p);
		int pktsize = ch->size()<<3;
		MTU=1500.0/40*pktsize;

		//Start timer
		shaper_timer_.resched(MTU/rate_);
	}

	//Get ACK packet destination address
	hdr_ip *ih=hdr_ip::access(p);
    int dst=ih->daddr();
	
	hdr_tcp *th=hdr_tcp::access(p);
	//seq number is ack number?
	int ack=th->seqno();
	//fprintf(stderr,"%d\n",ack);

	//tokens_=tokens_-(ack-flows_[dst-2])*MTU;
	//flows_[dst-2]=ack;	
	//The flow is not initialized, no TCP traffic has been received
	if(flows_[dst-2]==0)
	{
		//This flow is initialized
		flows_[dst-2]=1;
	}
	else//The flow has been initialized
	{
		//TCP traffic has been received.
		//Reduce on the flying TCP traffic
		//	DelAck 2 MTU
		//	TCPSink 1 MTU
		tokens_=tokens_-(delack_+1)*MTU;
	}

	//Enqueue ACK packet to flow queue appropriately
	if (q_[dst-2]->length()<qlen_)
	{
		q_[dst-2]->enque(p);
	}
	else 
	{
		drop(p);
	}
	double now=Scheduler::instance().clock();
	fprintf(stderr,"%f %d\r\n",now,(int)(tokens_/MTU*1500));
}

void SHAPER::timeout(int)
{
	//On the flying TCP traffic is larger than our threshold,we should not release ACK packets now
	if(tokens_>=thresh_/1500*MTU)
	{
		shaper_timer_.resched((delack_+2)*MTU/rate_);
		return;
	}

	//If on the flyinf TCP traffic is lower than our threshold, we could release ACK packets now
	int queue_number=-1;
	//int dst=-1;
	int i=0;
	
	//Fine the first flow queue which is not empty from iteration
	for(i=0;i<senders_;i++)
	{
		//Throw ACK packet at the head of queue and add tokens
		if(q_[(i+iteration)%senders_]->length() > 0)
		{
			//Get current queue id
			queue_number=(i+iteration)%senders_;
			Packet *p=q_[queue_number]->deque();

			//hdr_ip *ih=hdr_ip::access(p);
			//dst=ih->daddr();
			target_->recv(p);
			tokens_+=(delack_+2)*MTU;
	
			break;
		}
	}
	//getupdatedtokens();

	//An ACK packet has been released
	if(queue_number>=0)
	{
		iteration=(queue_number+1)%senders_;
	}
	//shaper_timer_.resched(MTU/rate_);
	
	
    if(tokens_<thresh_/1500*MTU)
	{
		shaper_timer_.resched((delack_+1)*MTU/rate_);
	}
	else
	{
		shaper_timer_.resched(((delack_+2)*MTU)/rate_);
	}
	double now=Scheduler::instance().clock();
	fprintf(stderr,"%f %d\r\n",now,(int)(tokens_/MTU*1500));
}

int SHAPER::command(int argc, const char*const* argv) 
{
      if(argc == 3) 
	  {
           if(strcmp(argv[1], "Reset") == 0) 
		   {
                  reset(atof(argv[2]));
                  return(TCL_OK);
           }
      }
      return(Connector::command(argc, argv));
}

void SHAPER_Timer::expire(Event* /*e*/)
{
	shaper_->timeout(0);
}

static class SHAPERClass : public TclClass {
public:
	SHAPERClass() : TclClass ("SHAPER") {}
	TclObject* create(int,const char*const*) {
		return (new SHAPER());
	}
}class_shaper;