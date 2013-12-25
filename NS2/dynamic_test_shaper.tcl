#arguments 
#Number of Servers (Senders)
#Buffer Size
#Pacing Speed
#Data Size

if { $argc !=7 } {
	puts "This script needs seven arguments [senders, switch buffer(packet), pacing rate(Mbps), SRU(Byte), bottleneck link bandwidth(Mbps), MSS(Byte), DelAck(0 or 1)]"
	#puts "The first argument is the number of senders"
	#puts "The second argument is the buffer size (packet)"
	#puts "The third argument is the pacing rate (Mbps)"
	#puts "The fourth argument is the data size (Byte)"
	#puts "The fifth argument is the bottleneck link bandwidth (Mbps)"
	#puts "The sixth argument is the size of MSS (Byte)"
	#puts "The seventh argument is whether the receiver supports the DelAck (0 and 1)"	
	exit 1  
} else {
	#puts [lindex $argv 0];
	#puts [lindex $argv 1];
	#puts [lindex $argv 2];
	#puts [lindex $argv 3];
}

#Senders
set senders [lindex $argv 0];
#Router Buffer Size
set bufSize [lindex $argv 1];
#pacing speed
set pacingSpeed [lindex $argv 2]Mb;
#SRU data size
set synchSize [lindex $argv 3];
#Bottleneck link bandwidth
set bw [lindex $argv 4]
set bottleneckBandwidth [lindex $argv 4]Mb;
#MSS
set mss [lindex $argv 5];
#DelAck
set delack [lindex $argv 6];


#puts $pacingSpeed

#Network Simulator
set ns [new Simulator]

#Colors
$ns color 1 red
$ns color 2 blue
$ns color 3 cyan
$ns color 4 green
$ns color 5 orange
$ns color 6 black
$ns color 7 yellow
$ns color 8 purple
$ns color 9 gold
$ns color 10 chocolate
$ns color 11 brown
$ns color 12 tan
$ns color 13 black
$ns color 14 pink
$ns color 15 magenta
$ns color 16 violet

set tracedir linux_flow
set runTimeInSec 5.0

set fall [open ./$tracedir/out.tra w]
$ns trace-all $fall

# create output files for bandwidth per nodes (moving average)
set f0 [open ./$tracedir/tput_moving.tr w]
set f1 [open ./$tracedir/tput_instantaneous.tr w]
set f2 [open ./$tracedir/rtt.tr w]
#set f2 [open ./$tracedir/tput_avg.tr w]

# record average bw statistics
set favg_ind [open ./$tracedir/tput_cum_ind_avg.tr w]
set favg_tot [open ./$tracedir/tput_cum_tot_avg.tr w]

# record queue size
set router_queue [open ./$tracedir/router w]
#set client_queue [open ./$tracedir/client w]

for { set k 0 } { $k<$senders } { incr k } {
	set avg($k) 0
	#Cumulative bandwidth 
	set bw_interval($k) 0.0
	#RTT
	set rtt($k) 0.0
	#Avg throughput for a specific period (senders*N*150microseconds)
	#set throughput($k) 0.0
	#History avg throughput
	#set throughput1($k) 0.0
	#set throughput2($k) 0.0
	#set throughput3($k) 0.0
	#Flow states
	#set flows($k) 0
}

set i 0
set old 0
set lastreset 0.1 
#Smooth link utilization
set proportion -1.0
#set iteration 0
#set thresh [expr $senders*3]

proc finish {} {

        global ns fall f0 f1 f2 favg_ind favg_tot tracedir router_queue senders 
        #f2
		$ns flush-trace

        #Close the output files
        close $f0
        close $f1
		close $f2
        close $favg_ind
        close $favg_tot
		close $router_queue
		
        exit 0
}

Queue/DropTail set bytes_ true
Queue/DropTail set queue_in_bytes_ true
Queue/DropTail set mean_pktsize_ 1500

#Settings for Linux TCP
Agent/TCP set maxrto_ 120
Agent/TCP set packetSize_ $mss 
#rto min 200ms
Agent/TCP set minrto_ 0.2
Agent/TCP set tcpTick_ 0.0000001
#Agent/TCP set overhead_ 0.0001
#Agent/TCP set overhead_ 0.0001
#Agent/TCP set dctcp_ true
#Agent/TCP set dctcp_g_ 0.0625
#Agent/TCP set ecn_ 1
#Agent/TCP set old_ecn 1
#Agent/TCP set slow_start_restart_ false
#Agent/TCP set tcpTick 0.01
#Agent/TCP set windowOption_ 0

#advertised window=3*ssthresh_
Agent/TCP set window_ 270

if { $delack==1 } {
	Agent/TCP set windowInit_ 3
}

#Agent/TCP set syn_ true
#Agent/TCP set tcpTick_ 0.0000001
#Agent/TCP set ts_resetRTO_ true
#Agent/TCP set delay_growth_ false

#Create ToR switch and Client
set client_node [$ns node]
set router [$ns node]


#Initialize token bucket filter 
set shaper [new SHAPER]
$shaper set bucket_ 105000
$shaper set rate_ $bottleneckBandwidth
$shaper set thresh_ 90000
$shaper set delack_ $delack
$shaper set qlen_ 100000
$shaper set senders_ $senders
$shaper set queue_thresh_ 1000000
 
$ns duplex-link $router $client_node $bottleneckBandwidth 30us DropTail

#Buffer for client 1000*1000Byte=1000000Byte=1M
$ns queue-limit $client_node $router 1000000
$ns queue-limit $router $client_node $bufSize


#Node id: for change bandwidth during the simulation 
set i1 [$client_node id]
set i2 [$router id]

set router_size [$ns monitor-queue $router $client_node $router_queue 0.0001]
#set client_size [$ns monitor-queue $client_node $router client_queue 0.001] 

#Record queue of router and client
proc recordQueue {} {
	global ns router_size router_queue pacingSpeed tbf tcp senders 
	set time 0.0001
	set now [$ns now]
	#$router_size instvar
	set queue_length [$router_size set size_]
	#puts $router_queue "$now [$router_size set size_]"
	if { $queue_length>20000 } {
            $ns at  [expr [$ns now]] "$tbf set rate_ 13.3Mb"
	    $ns at  [expr [$ns now]] "$tbf set size_ 200"

        } 
        if {$queue_length<15000 } {
 	    $ns at [expr [$ns now]] "$tbf set rate_ 26.6Mb"
	    $ns at [expr [$ns now]] "$tbf set size_ 300"
	} 
        
        
	if { [expr $now+$time]<3 } {
		$ns at [expr $now+$time] "recordQueue"
	}
}

#Dynamic adjust shaping speed based on CA/SS and Normal/DelAck
proc adjust {} {
	global ns tcp senders tbf delack bw
	set time 0.001
	set now [$ns now]
	set num 0
	
	#Calculate the number of flows coming to CA
	for { set j 0 } { $j<$senders } { incr j } {
		set tmp [ $tcp($j) set cwnd_]
		if { $tmp>20 } {
			incr num
		}  
	}
	
	#All flows come to CA
	if { $num==$senders } {
		set a [expr $bw/1000.0]
		#DelAck
		if { $delack==1 } {
			set rate [expr $a*13]Mb
			set size [expr $a*1300]
			$ns at	[expr $now+0.0001] "$tbf set rate_ $rate"
			$ns at  [expr $now+0.0001] "$tbf set bucket__ $size"
		} else {
			set rate [expr $a*(25.4)]Mb
			set size [expr $a*(2540)]

			$ns at	[expr $now] "$tbf set rate_ $rate"
			$ns at  [expr $now] "$tbf set bucket_ $size"
		}
	} else {
		if { [expr $now+$time]<3 } {
			$ns at [expr $now+$time] "adjust"
		}		
	}
}


#We use uniform distribution
set rng [new RNG]
$rng seed 0
set  r3  [new RandomVariable/Uniform] 
$r3  use-rng $rng 
$r3  set  min_ 20.0 
$r3  set  max_ 50.0
for { set k 0 } { $k<$senders } { incr k } {
	set server($k) [$ns node]
	set rtt($k) [expr int([$r3 value])]
	set delay $rtt($k)us
	$ns duplex-link $router $server($k) 1000Mb $delay DropTail
	
	puts $f2 $rtt($k)

	#create tcpsink for client_node
	if { $delack==0 } {
		set tcpc($k) [new Agent/TCPSink]
		$ns attach-shaper-agent $client_node $tcpc($k) $shaper
	} else {
		set tcpc($k) [new Agent/TCPSink/DelAck]
		$ns attach-shaper-agent $client_node $tcpc($k) $shaper	
	}
	#server_node_i
	set tcp($k) [new Agent/TCP/Newreno]
	$tcp($k) attach [open ./$tracedir/$k.tr w]
	$tcp($k) set bugFix_ false
	$tcp($k) trace cwnd_
	$tcp($k) trace ack_
    $tcp($k) trace srtt_
	$tcp($k) trace rtt_
	$tcp($k) trace ssthresh_
	$tcp($k) trace nrexmit_
	$tcp($k) trace nrexmitpack_
	$tcp($k) trace nrexmitbytes_
	$tcp($k) trace ncwndcuts_
	$tcp($k) trace ncwndcuts1_
	$tcp($k) trace dupacks_
	$ns attach-agent $server($k) $tcp($k)

	#connect the sending agents to sinks
	$ns connect $tcp($k) $tcpc($k)

	#Setup FTP over TCP connection
	set ftp($k) [new Application/FTP]
	$ftp($k) attach-agent $tcp($k)
	$ftp($k) set type_ FTP
	$ns at [expr 0.1+0.000004*$k*rand()] "$ftp($k) send $synchSize"
	
	set avg($k) 0
	set bw_interval($k) 0.0
	
}

proc record {} {
	global ns f0 f1 favg_ind favg_tot i tcpc tcp avg bw_interval senders shaper old lastreset proportion
	#f2 throughput throughput1 throughput2 throughput3 iteration thresh 
	
	# Set the time after which the procedure should be called again
	set time 0.00015
	set i [expr $i+$time]
	#Get the current time
	set now [$ns now]
	
	#Increase iteration
	#set iteration [expr $iteration+1]
	
	#if { $iteration>=$thresh } {
	#	puts $f2 $iteration
	#	set iteration 0
	#	set str $now
	#	for {set k 0} { $k<$senders } { incr k } {
	#		set throughput($k) [expr int($throughput($k)/$time/$thresh*8/1000000)]
	#		append str " "
	#		append str $throughput($k)
	#		set throughput1($k) $throughput2($k)
	#		set throughput2($k) $throughput3($k)
	#		set throughput3($k) $throughput($k)
	#		set throughput($k) 0.0
	#		if { $throughput1($k)>1000.0/$senders && $throughput1($k)>[expr 1.2*$throughput2($k)] && $throughput1($k)>=[expr 1.2*$throughput3($k)] } {
	#			set flows($k) 1
	#			$shaper Identify $k
	#		} 
	#		if { $throughput1($k)>1000.0/$senders && $throughput2($k)<1000.0/$senders && $throughput3($k)<1000.0/$senders  } {
	#			set flows($k) 1
	#			$shaper Identify $k
	#		}
	#	}
	#	puts $f2 $str
	#}
	
	set str $now
	#Record how many bytes have been received by the tcp sinks
	for {set k 0} { $k<$senders } { incr k } {
		set bw($k) [$tcpc($k) set bytes_]
		set bw_interval($k) [expr $bw_interval($k)+$bw($k)]
		#set throughput($k) [expr $throughput($k)+$bw($k)]
		append str " "			
		append str [expr int($bw_interval($k)/$i*8/1000000)]	
	}
	puts $f0 $str		
	
	#Calculate the bandwidth (in MBit/s) and write it to the files
	set str $now
	set sum 0	
	for {set k 0} { $k<$senders } { incr k } {
			append str " "
			append str [expr int($bw($k)/$time*8/1000000)]
			set sum [expr int($sum+$bw($k)/$time*8/1000000)]
			set avg($k) [expr { wide($avg($k)) +$bw($k) }]
			$tcpc($k) set bytes_ 0	
	}
	puts $f1 $str
	
	if { $proportion==-1.0 && $sum>950 } {
		set proportion [expr 1]
	} 
	if { $proportion>=0 } {
	
		set proportion [expr 0.25*$proportion+0.75*$sum/1000.0] 
	
	}

	#If incoming packets are not back to back, we may reset switch buffer occupation	
	if { $sum<900 && $old>950 || $sum==0 } {
	
		#Calculate interval since last reset
		set tmp [expr $now-$lastreset]
		#Interval is larger than 450 microseconds
		if { $tmp>0.0006 } {
			$shaper Reset [expr max($proportion,0.2)]
			set lastreset $now
		}
	}
	
	#Re-schedule the procedure
	if { $now+$time<1 } {
		set old $sum
		$ns at [expr $now+$time] "record"
	}

}

$ns at 0.1 "record"
$ns at $runTimeInSec "finish"
$ns run





