#!/usr/bin/perl

=head1 NAME

Nagios::NRPE::Daemon - A Nagios NRPE Daemon

=head1 SYNOPSIS

 use Nagios::NRPE::Daemon;

 my $commandlist = {
  "check_cpu" => { bin => "/usr/lib/nagios/plugin/check_cpu",
                   args => "-w 50 -c 80" }
 };

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

  bless $self,$class;
}

sub start{
  my $self = shift;
  my $socket;
  my $packet = Nagios::NRPE::Packet->new();
  if ($self->{ssl}) {
    # eval {
    #   # required for new IO::Socket::SSL versions
    #   require IO::Socket::SSL;
    #   IO::Socket::SSL->import();
    #   IO::Socket::SSL::set_ctx_defaults( SSL_verify_mode => 0 );
    # };
    # $socket = IO::Socket::SSL->new($self->{host}.':'.$self->{port})
    #   or die(IO::Socket::SSL::errstr());
  } else {
    $socket = IO::Socket::INET->new(
      LocalAddr => $self->{host},
      LocalPort => $self->{port},
      Listen => 100,
      Proto    => 'tcp',
      Type     => SOCK_STREAM) or die "ERROR: $@ \n";
  }
  $socket->listen();
  $socket->autoflush(1);
  my $client;

  while ( $client =  $socket->accept() ) {
    my $response;
    while (<$client>) {

      print Dumper($packet->deassemble($_));
      $response .= $_;
    }
    print $client $packet->assemble(type => NRPE_PACKET_RESPONSE,
				    check => "Thanks This was Helpfull!",
				    version => NRPE_PACKET_VERSION_2 );
    close $client;
    last;
  }
  $client->close;
  print "Finished communication!\n";
}

sub stop {
  my $self = shift;
}
1;
