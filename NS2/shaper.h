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
 
#ifndef ns_shaper_h
#define ns_shaper_h
	
#include "connector.h"
#include "timer-handler.h"

class SHAPER;

class SHAPER_Timer : public TimerHandler {
public:
	SHAPER_Timer(SHAPER *t) : TimerHandler() { shaper_ = t;}
	
protected:
	virtual void expire(Event *e);
	SHAPER *shaper_;
};


class SHAPER : public Connector {
public:
	SHAPER();
	~SHAPER();
	void timeout(int);
protected:
/*
 * Command function
 * 1.Reset value
 */
	int command(int argc, const char*const* argv);
//Recv packet
	void recv(Packet *, Handler *);
/*
 * Reset on the flying TCP traffic to a value
 * k is a ratio. New value=k/2*Old value
 */
	void reset(double k);
//On the flying TCP traffic 
	double tokens_; 
//Bottleneck link bandwidth
	double rate_; 
//Bucket depth: equal to available switch buffer
	int bucket_; 
//Max threshold of on the flying TCP traffic
	double thresh_; 
//1:DelAck 0:TCPSink
	int delack_; 
//Length of packet queue to buffer packets
	int qlen_;
//Length of MTU(bits)
	double MTU;
//PacketQueue array for each flow
	PacketQueue **q_;
//Timer
	SHAPER_Timer shaper_timer_;
//Object is initialized
	int init_;
//Number of flows(senders)
	int senders_;
//States of flows (start or not)
	int *flows_;
//Iteration to release ACK packets
	int iteration;
//RTT threshold
	double queue_thresh_;

};

#endif