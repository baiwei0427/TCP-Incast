#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h> 
#include <sys/time.h>
#include <pthread.h>
 
void client_test(char* IPaddress, int port, int size);
//Set send window
void set_send_window(int sockfd, int window);
//Set receive window
void set_recv_window(int sockfd, int window);

int main(int argc, char **argv)
{
	client_test("192.168.1.41",5001,64);
	return 0;
}

//IPaddress e.g. "192.168.1.100"
//port e.g. 5001
//size e.g. "64"->64KB
void client_test(char* IPaddress, int port, int size)
{
	int sockfd;
	struct sockaddr_in servaddr;
	int len;
	char data_size[6]={0};
	char buf[BUFSIZ];
	struct timeval tv_start;
	struct timeval tv_end;
	
	//Init sockaddr_in
	memset(&servaddr,0,sizeof(servaddr));
	servaddr.sin_family=AF_INET;
	//IP address
	servaddr.sin_addr.s_addr=inet_addr(IPaddress);
	//Port number
	servaddr.sin_port=htons(port);
	
	//Convert int to char*
	sprintf(data_size,"%d",size);
	
	//Init socket
	if((sockfd=socket(PF_INET,SOCK_STREAM,0))<0)
	{
		perror("socket error\n");  
		return;  
	}
	
	set_recv_window(sockfd, 512000);
	set_send_window(sockfd, 32000);
	
	//Establish connection
	if(connect(sockfd,(struct sockaddr *)&servaddr,sizeof(struct sockaddr))<0)
	{
		perror("connect error\n");
	}
	
	//Get start time
	gettimeofday(&tv_start,NULL);
	
	//Send Request
	len=send(sockfd,data_size,strlen(data_size),0);
	
	//Recv Data from Server
	while(1)
	{
		len=recv(sockfd,buf,BUFSIZ,0);
		if(len<=0)
			break;
	}
	
	//Get end time
	gettimeofday(&tv_end,NULL);
	close(sockfd);
	
	//Time interval (unit: microsecond)
	unsigned long interval=(tv_end.tv_sec-tv_start.tv_sec)*1000000+(tv_end.tv_usec-tv_start.tv_usec);
	//KB->bit 1024*8
	int throughput=size*1024*8/interval;
	printf("0-%lu ms, %d KB, %d Mbps\n",interval/1000,size,throughput);
}

void set_recv_window(int sockfd, int rcvbuf)
{
	//rcvbuf is twice the clamp
	//int clamp=rcvbuf/2;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char *)&rcvbuf, sizeof(rcvbuf));
	//setsockopt(sockfd, SOL_SOCKET, TCP_WINDOW_CLAMP, (char *)&clamp, sizeof(clamp));
}

void set_send_window(int sockfd, int sndbuf)
{
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));
}