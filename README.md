TCP-Incast
==========

Mitigate TCP Incast congestion with Proactive ACK Control (PAC). We implement PAC as a Linux Kernel Module (LKM) and do extensive evaluation in testbed. Our experiments show PAC can support 100 concurrent connections while maintaing high throughput.  

People
==========

Wei Bai (baiwei0427@gmail.com) 

Department of Computer Science and Engineering, Hong Kong University of Science and Technology

Prof. Kai Chen

Department of Computer Science and Engineering, Hong Kong University of Science and Technology

Haitao Wu

Microsoft Redmond (previous in Wireless and Networking Group, Microsoft Research Asia)

References
=========
Data Center TCP (SIGCOMM 2010)

ICTCP: Incast Congestion Control for TCP in Data Center Networks (CoNEXT 2010 Best paper)

Safe and effective fine-grained TCP retransmissions for datacenter communication (SIGCOMM 2009)

Tuing ECN for data center networks (CoNEXT 2012)

Bugs
=========
I find a potential bug in current DCTCP (TCP/ECN) imeplmentation. The ECN standard deﬁnes ECN-capable (ECT) bits at the IP header to indicate switches that mark the packet.  However, the behavior of switches handling non-ECT packets when ECN is triggered is not speciﬁed. Our broadcom switch with ECN simply drops non-ECT packets when queuing lengh exceeds the threshold. The ECN standards claims that TCP retransmitted packets and SYN packets should not be marked with ECT. When these packets go through the bottleneck switch, they are likely to be dropped. Tuning ECN (CoNEXT 2012) has pointed out this problem. However, in current public DCTCP implementation (http://simula.stanford.edu/~alizade/Site/DCTCP.html) in Linux kernel 2.6.38.3, this problem does exist, greatly influencing the peformance of DCTCP, especially in incast congestion. 

To solve this problem, there are mainly two kinds of solutions. One is to modify your switch which is not convenient. The other solution is to mark ECT bits on end hosts using iptables/Netfilter. You can use following command to achieve this:

iptables -A OUTPUT -t mangle -p tcp -j TOS --set-tos 2    
