################################################################
# -*- perl -*-
#
# INetSim::PortDetector - INetSim auto detector for open ports
# detect whether configured tcp/udp ports are opened or not
#
#################################################################

package INetSim::PortDetector;

use strict;
use warnings;

use Socket;
use IO::Select;

#################################
# global variable, when use the package, they will be processed
my $remote_ip = undef;		# remote ip to probe
my $bind_port = undef;		# service bind port
my $bind_ip = undef;		# service bind ip
my @tcp_port_list = undef;	# remote tcp port list to probe
my @udp_port_list = undef;	# remote udp port list to probe
my $wait_time_for_message = undef;		# wait after send default message
my $delay_for_next_round = undef;
my $default_send_message = undef;		# default message to send for udp/tcp
my $service_name = undef;
###################################

# main loop
sub main_loop{
	
	# set configure
	&configure;
	
	# set signal handle
	local $SIG{'INT'} = sub{&terminate_service};
	local $SIG{'HUP'} = sub{&terminate_service};
	local $SIG{'TERM'} = sub{&terminate_service};
	
	# untained data
	$remote_ip = $1 if ($remote_ip =~ /^(.+)$/);
	$bind_port = $1 if ($bind_port =~ /^(.+)$/);
	$bind_ip = $1 if ($bind_ip =~ /^(.+)$/);
	
	# local and remote info
	my $remote_iaddr = inet_aton($remote_ip) || die "no host:$remote_ip"; 
	my $remote_paddr = undef;
	my $local_iaddr = inet_aton($bind_ip) || die "no host:$bind_ip";
	# untained data
	$local_iaddr = $1 if ($local_iaddr =~ /^(.+)$/);
	my $local_paddr = sockaddr_in($bind_port, $local_iaddr);
	my $udp_proto = getprotobyname("udp");
	my $tcp_proto = getprotobyname("tcp");
	
	my $select = new IO::Select();
	my $connect_timeout = 0.1;
	
	# tell service is up
	$0 = "inetsim_" . $service_name;
	&INetSim::Log::MainLog("started (PID $$)", $service_name);
	# delay for service to setup
	sleep(2);
	while (1){
		# try connect the port in tcp_port_list
		# firstly, we use connection func to decide whether target port is opened or not
		# next, we can borrow from scanner like nmap/sniffer to detect opened ports, same as udp
		foreach my $tcp_port (@tcp_port_list){
			# create tcp socket
			socket(my $tcp_sock, PF_INET, SOCK_STREAM, $tcp_proto) || &INetSim::Log::SubLog("$service_name create tcp socket failed", $service_name, $$);
			# set socket to be reusable
			setsockopt($tcp_sock, SOL_SOCKET, SO_REUSEADDR, 1) || &INetSim::Log::SubLog("$service_name set sock option failed", $service_name, $$);
			# bind tcp socket, may remove in future
			bind($tcp_sock, $local_paddr) || &INetSim::Log::SubLog("$service_name bind tcp socket failed", $service_name, $$);
			$remote_paddr = sockaddr_in($tcp_port, $remote_iaddr);
			
			# try connect
			$tcp_sock = &wrap_connect($tcp_sock, $remote_paddr, $connect_timeout);
			if ($tcp_sock){
				&INetSim::Log::SubLog("$remote_ip:$tcp_port/tcp opened", $service_name, $$);
				# read message at first
				&read_socket($tcp_sock, $tcp_port, $wait_time_for_message);
				# send default message
				print $tcp_sock $default_send_message;
				&INetSim::Log::SubLog("Send defualt message to $remote_ip:$tcp_port/tcp", $service_name, $$);
				# read reponse
				&read_socket($tcp_sock, $tcp_port, $wait_time_for_message);
				# close socket
				close($tcp_sock);
			}else{
				 &INetSim::Log::SubLog("$remote_ip:$tcp_port/tcp closed or filtered", $service_name, $$);
			}
		}
		
		# send message for every remote udp port and wait a reponse
		foreach my $udp_port (@udp_port_list){
			# create and bind udp soket for every port to probe
			socket(my $udp_sock, PF_INET, SOCK_DGRAM, $udp_proto) || &INetSim::Log::SubLog("$service_name create udp socket failed, at", $service_name, $$);
			bind($udp_sock, $local_paddr) || &INetSim::Log::SubLog("$service_name bind udp socket failed", $service_name, $$);
			$remote_paddr = sockaddr_in($udp_port, $remote_iaddr);
			if (!defined send($udp_sock, $default_send_message, 0, $remote_paddr)){
				&INetSim::Log::SubLog("Send message to $remote_ip:$udp_port/udp failed", $service_name, $$);
				next;
			}else{
				&INetSim::Log::SubLog("Send message to $remote_ip:$udp_port/udp", $service_name, $$);
				# send may return success but destination may not reachable
				# wait for a message
				&read_socket($udp_sock, $udp_port, $wait_time_for_message);
			}
			# close socket and remove it from select
			close($udp_sock);
			$select->remove($udp_sock);
		}
		# start next time
		sleep($delay_for_next_round);
		&INetSim::Log::SubLog("Start next round port detection\n", $service_name, $$);
	}
}


sub read_socket{
	my $sock = shift;
	my $peer_port = shift;
	my $wait_time_for_message = shift;
	my $sock_type = "tcp";	# here just tcp/udp type socket
	$sock_type = "udp" if (unpack("L", getsockopt($sock, SOL_SOCKET, SO_TYPE)) == SOCK_DGRAM);
	if (!defined $sock || !defined $wait_time_for_message || !defined $peer_port){
		&INetSim::Log::SubLog("call sub read_socket without correct parameters", $service_name, $$);
		return;
	}
	my $select = new IO::Select($sock);
	# read reponse
	my $response = undef;
	my @socket_ready = $select->can_read($wait_time_for_message);
	if (!scalar @socket_ready){
		# no ready socket for reading, mean no data arrival
		if ($sock_type eq "udp"){
			# remote port may be closed(receive icmp_unreacheable<type 3, code 3>)
		    # or iltered(receive icmp_unreacheable<type 3, not 3>), even be opened if 
		    # we send a unexpected packet to a remote open port and it decided to drop
		    # the packet.
			&INetSim::Log::SubLog("$remote_ip:$peer_port/$sock_type closed or filtered", $service_name, $$);
		}else{
			# wer read socket when socket is connected, we may send invalid message, just log No response
			&INetSim::Log::SubLog("No response from $remote_ip:$peer_port/$sock_type after $wait_time_for_message seconds", $service_name, $$);
		} 
	}else{
		# read reponse
		my $peer_paddr = recv($sock, $response, 512, 0);
		if (!defined $peer_paddr){
		 	# strange error, return ready for read but read failed
		 	&INetSim::Log::SubLog("recv error with $remote_ip:$peer_port/$sock_type, $!", $service_name, $$);
		}elsif(defined $response){
		 	# convert non-printable char to '<NP>' before log
		 	$response =~ s/[^\x20-\x7e]/\<NP\>/g;
		 	if ($sock_type eq "udp"){
		 		# receive response, remote port is opened
		 		&INetSim::Log::SubLog("$remote_ip:$peer_port/$sock_type opened", $service_name, $$);
		 	}
		 	&INetSim::Log::SubLog("received from $remote_ip:$peer_port/$sock_type: $response", $service_name, $$);
		}else{
			# should not happen
			&INetSim::Log::SubLog( "unkown recv error with $remote_ip:$peer_port/$sock_type", $service_name, $$);
		}
	}
	#remove select
	undef $select;
}


# reference: http://devpit.org/wiki/Connect()_with_timeout_(in_Perl)
sub wrap_connect{
	use Errno;
	use Fcntl;
	my $sock = shift;
	my $peer_paddr = shift;
	my $time_out = shift;
	# Set autoflushing.
    $_ = select($sock); $| = 1; select $_;

    # Set FD_CLOEXEC.
    $_ = fcntl($sock, F_GETFL, 0) or return undef;
    fcntl($sock, F_SETFL, $_ | FD_CLOEXEC) or return undef;
    
    # Set O_NONBLOCK so we can time out connect().
    if ($time_out){
    	$_ = fcntl($sock, F_GETFL, 0) or return undef;  # 0 for error, 0e0 for 0.
    	fcntl($sock, F_SETFL, $_ | O_NONBLOCK) or return undef;  # 0 for error, 0e0 for 0.
    }
    
    # Connect returns immediately because of O_NONBLOCK.
    connect($sock, $peer_paddr) or $!{EINPROGRESS} or return undef;
    
    # not set timeout
    return $sock unless $time_out;
    
    # Reset O_NONBLOCK.
    $_ = fcntl($sock, F_GETFL, 0) or return undef;  # 0 for error, 0e0 for 0.
    fcntl($sock, F_SETFL, $_ & ~ O_NONBLOCK) or return undef;  # 0 for error, 0e0 for 0.
    
    # original version
    # Use select() to poll for completion or error. When connect succeeds we can write.
    #my $vec = "";
    #vec($vec, fileno($sock), 1) = 1;
    #select(undef, $vec, undef, $time_out);
    #unless(vec($vec, fileno($sock), 1)) {
    #	# If no response yet, impose our own timeout.
    #   $! = Errno::ETIMEDOUT();
    #    #print "connect error: $!\n";
    #    return undef;
    #}
    # This is how we see whether it connected or there was an error. Document Unix, are you kidding?!
    #$! = unpack("L", getsockopt($sock, SOL_SOCKET, SO_ERROR));
    #if ($!){
    #	print "connect eroror: $!\n";
    #	return undef;
    #};
    #return $sock;
    
    # use select to check connection state in timeout
    my $select = new IO::Select($sock);
    my $ready_socket = $select->can_write($time_out);
    undef $select;
    # if timeout, the socket error state may not be set, ie is 0.
    my $sock_error = unpack("L", getsockopt($sock, SOL_SOCKET, SO_ERROR));
    if ($ready_socket && ($sock_error == 0)){
    	return $sock;
    }else{
    	# time out($sock_error ==  0) or error<$sock_error is set>
    	return undef;
    }
}


sub configure{
	$remote_ip = &INetSim::Config::getConfigParameter("PDS_Default_Remote_Addr");
	$bind_port = &INetSim::Config::getConfigParameter("PDS_Default_Bind_Port");
	$bind_ip = &INetSim::Config::getConfigParameter("PDS_Default_Bind_IP");	# bind to '0.0.0.0' so it call probe all interface
	@tcp_port_list = &INetSim::Config::getConfigArray("PDS_Remote_TCP_Port_List") || (21,6667);
	@udp_port_list = &INetSim::Config::getConfigArray("PDS_Remote_UDP_Port_List") || (69,37);
	$wait_time_for_message = 0.1;	# after send default message
	$delay_for_next_round = &INetSim::Config::getConfigParameter("PDS_Next_Detection_Delay");
	$default_send_message = &INetSim::Config::getConfigParameter("PDS_Default_Send_Message");
	$service_name = &INetSim::Config::getConfigParameter("PDS_ServiceName");
}


sub terminate_service{
	&INetSim::Log::MainLog("stopped (PID $$)", $service_name);
	exit(0);
}


sub error_exit{
	my $message = shift;
	if (! defined $message){
		$message = "Unknown error";
	}
	&INetSim::Log::MainLog("$service_name terminated with errror: $message", $service_name);
	exit(1);
}


1;