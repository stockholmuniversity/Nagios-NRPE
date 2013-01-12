#!/usr/bin/perl

=head1 NAME

Nagios::NRPE::Daemon - A Nagios NRPE Daemon

=head1 SYNOPSIS

 use Nagios::NRPE::Daemon;
 use IPC::Cmd qw(can_run run run_forked);

 # create the commandlist we accept
 my $commandlist = 
 };
 my $callback = sub {
   my ($self,$check,@options) = @_;
   my $commandlist = $self->commandlist();
   if ($commandlist->{$check}) {
     my $args = $commandlist->{$check}->{args};
     my $i = 0;
     foreach (@options) {
       $i++;
       $args =~ "s/\$ARG$i\$/$_/";
     }
     my $buffer;
     if (scalar run(command => $commandlist->{$check}->{bin} . " " . $args,
 		    verbose => 0,
		    buffer => \$buffer,
		    timeout => 20)) {
       return $buffer;
     }
   }
 };

 my $daemon = Nagios::NRPE::Daemon->new(
   listen => "127.0.0.1",
   port => "5666",
   pid_dir => '/var/run',
   ssl => 0,
   commandlist => {
     "check_cpu" => { bin => "/usr/lib/nagios/plugin/check_cpu",
                      args => "-w 50 -c 80" }
   },
   callback => $callback
 );
=head1 DESCRIPTION

=cut

package Nagios::NRPE::Daemon;

our $VERSION = '0.001';

use 5.010_000;

use strict;
use warnings;
use Data::Dumper;
use Carp;
use IO::Socket;
use IO::Socket::INET;
use Nagios::NRPE::Packet qw(NRPE_PACKET_VERSION_2
			    NRPE_PACKET_RESPONSE
			    MAX_PACKETBUFFER_LENGTH
			    STATE_UNKNOWN
			    STATE_CRITICAL
			    STATE_WARNING
			    STATE_OK);

sub new {
  my ($class,%hash) = @_;
  my $self = {};

  $self->{listen} = delete $hash{listen} || "0.0.0.0";
  $self->{port} = delete $hash{port} || "5666";
  $self->{pid_dir} = delete $hash{pid_dir} || "/var/run";
  $self->{ssl} = delete $hash{ssl} || 0;
  $self->{commandlist} = delete $hash{commandlist} || {};
  $self->{callback} = delete $hash{callback} || sub{};

  bless $self,$class;
}

sub start{
  my $self = shift;
  my $packet = Nagios::NRPE::Packet->new();
  my $callback = $self->{callback};
  my ($socket,$s);
  $socket = $self->create_socket();

  while (1) {
    while(($s = $socket->accept())) {
      my $request;
      $s->recv($request,1036);
      my $unpacked_request = $packet->deassemble($request);
      my $buffer = $unpacked_request->{buffer};
      my ($command,@options) = split /!/,$buffer;

      my $return = $self->{callback}($self,$command,@options);

      print Dumper($unpacked_request);
      print $s $packet->assemble(version =>NRPE_PACKET_VERSION_2,
				 type => NRPE_PACKET_RESPONSE,
				 check => $return
				);

      close($s);
    }
  }
}

sub stop {
  my $self = shift;
}

sub commandlist {
  my $self = shift;
  return $self->{commandlist};
}

sub create_socket {
  my $self = shift;
  my $socket;

  if ($self->{ssl}) {
    eval {
      # required for new IO::Socket::SSL versions
      require IO::Socket::SSL;
      IO::Socket::SSL->import();
      IO::Socket::SSL::set_ctx_defaults( SSL_verify_mode => 0 );
    };
    $socket = IO::Socket::SSL->new(
      Listen => 5,
      LocalAddr => $self->{host},
      LocalPort => $self->{port},
      Proto    => 'tcp',
      Reuse    => 1,
      SSL_verify_mode => 0x01,
      Type     => SOCK_STREAM)
      or die(IO::Socket::SSL::errstr());
  } else {
    $socket = IO::Socket::INET->new(
      Listen => 5,
      LocalAddr => $self->{host},
      LocalPort => $self->{port},
      Reuse    => 1,
      Proto    => 'tcp',
      Type     => SOCK_STREAM) or die "ERROR: $@ \n";
  }
  return $socket;
}
1;










