import socket 
import sys
import threading  
import string

class myThread (threading.Thread):
    def __init__(self,ip_address,command):
        threading.Thread.__init__(self)
        self.ip = ip_address
        self.cmd = command
		
    def run(self):
		s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((self.ip,10086))
		s.send(self.cmd)
		s.close()
		
		
def usage():
	sys.stderr.write('Usage of this script:\n')
	sys.stderr.write('incast.py [Senders] [Data Size] [Parallel Connections]\n')

	
if len(sys.argv)!=4:
	usage()

else:
	senders=(int)(sys.argv[1])
	data=sys.argv[2]
	connections=sys.argv[3]

	arr=[\
	'192.168.1.41',\
	'192.168.1.42',\
	'192.168.1.43',\
	'192.168.1.44',\
	'192.168.1.45',\
	'192.168.1.46',\
	'192.168.1.47',\
	'192.168.1.48',\
	'192.168.1.49',\
	'192.168.1.50',\
	'192.168.1.51',\
	'192.168.1.52',\
	'192.168.1.53',\
	'192.168.1.54',\
	'192.168.1.55']
	
	threads=[]

	for i in range(0,senders):
		command='iperf -c 192.168.1.40 -n '+data+'KB -P '+connections+' -p '+str(i%4+5001)+'\n'
		threads.append(myThread(arr[i],command))

	for i in range(0,senders):
		threads[i].start()