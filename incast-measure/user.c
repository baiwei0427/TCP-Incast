#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <strings.h>
#include <string.h>

/** Self-defined protocol type **/
#define NETLINK_TEST 31 

//Message Type
#define NLMSG_OUTPUT 0x11
//Max Payload Length 
#define MAX_PAYLOAD 1024

struct sockaddr_nl src_addr, dst_addr;
struct iovec iov;
int sockfd;
struct nlmsghdr *nlh = NULL;
struct msghdr msg;

int main( int argc, char **argv)
{
    //if (argc != 2) {
    //    printf("usage: ./a.out <str>\n");
    //    exit(-1);
    //}
	
	// create NETLINK_TEST socket
    sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST); 
	if (sockfd < 0)
	{
		printf("Cannot create socket\n");
		return -1;
	}
   
	/* create source address to listen  */
    memset(&src_addr,0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
	//Get process id
    src_addr.nl_pid = getpid();
	//no multicast
    src_addr.nl_groups = 0; 
    //Listen on src_addr
	bind(sockfd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    /* create destination address to send message */
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
	//kernel space, no process id
    dst_addr.nl_pid = 0; 
	//no multicast
    dst_addr.nl_groups = 0; 

    /* create messgae */
    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));

	// Fill the netlink message header 
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD); 
    nlh->nlmsg_pid = getpid();  /* self pid */
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = NLMSG_OUTPUT;

    strcpy(NLMSG_DATA(nlh), "Get Throughput\n");
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

	//send message
	//printf("Sending message to kernel\n");
    sendmsg(sockfd, &msg, 0);
	//printf("Waiting for message from kernel\n");

    /* receive message */
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    recvmsg(sockfd, &msg, 0);
    printf("Receive message payload: %s\n",(char *)NLMSG_DATA(nlh));

	close(sockfd);
	return 0;
}
