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

//Start TCP server
void start_server(int port);
//Function to deal with an incoming connection
void* server_thread_func(void* client_sockfd_ptr);
//Set send window
void set_send_window(int sockfd, int window);
//Print usage information
void usage();

int main(int argc, char **argv)
{
	if(argc!=2)
	{
		usage();
		return 0;
	}
	start_server(atoi(argv[1]));
	return 0;
}

void usage()
{
	printf("./server.o [port]\n");
}
void start_server(int port)
{
	//Socket for server
	int server_sockfd; 
	//Socket for client (incoming connection)
	int client_sockfd;
	
	//Server address
	struct sockaddr_in server_addr;
	//Client address
	struct sockaddr_in client_addr;

	memset(&server_addr,0,sizeof(server_addr)); 
	//IP protocol
    server_addr.sin_family=AF_INET;
	//Listen on "0.0.0.0" (Any IP address of this host)
    server_addr.sin_addr.s_addr=INADDR_ANY;
	//Specify port number
    server_addr.sin_port=htons(port); 
	
	//Init socket
	if((server_sockfd=socket(PF_INET,SOCK_STREAM,0))<0)  
	{    
		perror("socket error");  
		return;  
	}

	//Bind socket on IP:Port
	if(bind(server_sockfd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr))<0)  
	{  
		perror("bind error");  
		return;  
	}
	
	//Start listen
	//The maximum number of concurrent connections is 50
	listen(server_sockfd,50);  
	int sin_size=sizeof(struct sockaddr_in); 
	
	while(1)
	{
		if((client_sockfd=accept(server_sockfd,(struct sockaddr *)&client_addr,&sin_size))<0)  
		{  
			perror("accept error");  
			return;  
		}  
		
		//Start a new thread to deal with client_sockfd
		pthread_t server_thread;
		if(pthread_create(&server_thread, NULL , server_thread_func , (void*)&client_sockfd) < 0)
		{
			perror("could not create thread");
			return;
		}	
	}
}

void* server_thread_func(void* client_sockfd_ptr)
{
	int i;
	int sock=*(int*)client_sockfd_ptr;
	char write_message[BUFSIZ+1];
	char read_message[10]={0};
	int len;
	int data_size;
	
	memset(write_message,1,BUFSIZ);
	write_message[BUFSIZ]='\0';
	len=recv(sock,read_message,10,0);
	data_size=atoi(read_message);
	
	int loop=data_size/(BUFSIZ/1000);
	//printf("%d\n", loop);
	for(i=0;i<loop;i++)
	{
		//printf("%d\n",strlen(write_message));
		send(sock,write_message,strlen(write_message),0);
	}
	
	close(sock);
	return((void *)0);
}

void set_send_window(int sockfd, int sndbuf)
{
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf, sizeof(sndbuf));
}
