# -*- perl -*-
#
# INetSim::Time::TCP - A fake TCP time server
#
# RFC 868 - Time Protocol
#
# (c)2007-2009 Matthias Eckert, Thomas Hungenberg
#
# Version 0.47  (2009-10-28)
#
# For history/changelog see bottom of this file.
#
#############################################################

package INetSim::Time::TCP;

use strict;
use warnings;
use base qw(INetSim::Time);

use constant TIME_ADJ => 2208988800;



sub configure_hook {
    my $self = shift;

    $self->{server}->{host}   = &INetSim::Config::getConfigParameter("Default_BindAddress"); # bind to address
    $self->{server}->{port}   = &INetSim::Config::getConfigParameter("Time_TCP_BindPort");  # bind to port
    $self->{server}->{proto}  = 'tcp';                                      # TCP protocol
    $self->{server}->{user}   = &INetSim::Config::getConfigParameter("Default_RunAsUser");       # user to run as
    $self->{server}->{group}  = &INetSim::Config::getConfigParameter("Default_RunAsGroup");    # group to run as
    $self->{server}->{setsid} = 0;                                       # do not daemonize
    $self->{server}->{no_client_stdout} = 1;                             # do not attach client to STDOUT
    $self->{server}->{log_level} = 0;                                    # do not log anything

    $self->{servicename} = &INetSim::Config::getConfigParameter("Time_TCP_ServiceName");
    $self->{max_childs} = &INetSim::Config::getConfigParameter("Default_MaxChilds");
}



sub pre_loop_hook {
    my $self = shift;

    $0 = "inetsim_$self->{servicename}";
    &INetSim::Log::MainLog("started (PID $$)", $self->{servicename});
}



sub pre_server_close_hook {
    my $self = shift;

    &INetSim::Log::MainLog("stopped (PID $$)", $self->{servicename});
}



sub fatal_hook {
    my $self = shift;

    &INetSim::Log::MainLog("failed!", $self->{servicename});
    exit 0;
}



sub process_request {
    my $self = shift;
    my $client = $self->{server}->{client};
    my $rhost = $self->{server}->{peeraddr};
    my $rport = $self->{server}->{peerport};
    my $stat_success = 0;

    &INetSim::Log::SubLog("[$rhost:$rport] connect", $self->{servicename}, $$);
    if ($self->{server}->{numchilds} >= $self->{max_childs}) {
        print $client "Maximum number of connections ($self->{max_childs}) exceeded.\n";
        &INetSim::Log::SubLog("[$rhost:$rport] Connection refused - maximum number of connections ($self->{max_childs}) exceeded.", $self->{servicename}, $$);
    }
    else {
        my $cur_time = &INetSim::FakeTime::get_faketime();
        print $client pack('N', $cur_time + TIME_ADJ);
        &INetSim::Log::SubLog("[$rhost:$rport] send: " . scalar localtime($cur_time), $self->{servicename}, $$);
        $stat_success = 1;
    }
    &INetSim::Log::SubLog("[$rhost:$rport] disconnect", $self->{servicename}, $$);
    &INetSim::Log::SubLog("[$rhost:$rport] stat: $stat_success", $self->{servicename}, $$);
}



1;
#############################################################
#
# History:
#
# Version 0.47  (2009-10-28) me
# - improved some code parts
#
# Version 0.46  (2008-08-27) me
# - added logging of process id
#
# Version 0.45  (2007-12-31) th
# - change process name
#
# Version 0.44  (2007-04-26) th
# - use getConfigParameter
#
# Version 0.43  (2007-04-21) me
# - added logging of status for use with &INetSim::Report::GenReport()
#
# Version 0.42  (2007-04-10) th
# - get fake time via &INetSim::FakeTime::get_faketime()
#   instead of accessing $INetSim::Config::FakeTimeDelta
#
# Version 0.41  (2007-04-05) th
# - changed check for MaxChilds, BindAddress, RunAsUser and
#   RunAsGroup
#
# Version 0.4   (2007-03-26) th
# - split TCP and UDP servers to separate modules
# - rewrote module to use INetSim::GenericServer
# - added logging of refused connections
#
# Version 0.3b  (2007-03-15) me
#
#############################################################
