#!/usr/bin/perl

=head1 NAME

Nagios::NRPE::Packet - Assembly and de-assembly of an NRPE packet

=head1 SYNOPSIS

 use IO::Socket;
 use IO::Socket::INET;
 # Import necessary constants into Namespace
 use Nagios::NRPE::Packet qw(NRPE_PACKET_VERSION_2
                             NRPE_PACKET_QUERY
                             MAX_PACKETBUFFER_LENGTH
                             STATE_UNKNOWN
                             STATE_CRITICAL
                             STATE_WARNING
                             STATE_OK);

 my $packet = Nagios::NRPE::Packet->new();

 my $socket = IO::Socket::INET->new(
                    PeerAddr => $host,
                    PeerPort => $port,
                    Proto    => 'tcp',
                    Type     => SOCK_STREAM) or die "ERROR: $@ \n";

 print $socket $packet->assemble(type => QUERY_PACKET,
                              buffer => "check_load 1 2 3",
                              version => NRPE_PACKET_VERSION_2 );

 my $data = <$socket>
 my $response = $packet->deassemble($data);

 print $response->{buffer};

=head1 DESCRIPTION

This class is meant to be used when an active connection exists and is ready to send the
packet.

=head1 CONSTRUCTION

=over

=item new

Takes the following options as a hashref

=back

=head1 FUNCTIONS

Following functions can be used after the creation of the packet

=over 2

=item * assemble

Takes a hash of options defining the packet to be sent and returns the assembled packet. You can print this
to an open socket and send it to either a server or the client depending on your situation.

 check

A string defining the check to be run or the output of a check eg: "check_cpu"
NOTE: Nagios can accept arguments appended to the check in the form: "check_somecheck!ARG1!ARG2!ARG..."

 version

The NRPE version you want to use (currently only V2 is accepted).

See CONSTANTS for options here.

 type

The TYPE of packet you wish to send, which is either QUERY or RESPONSE.

See CONSTANTS for options here.

 result_code

This is a curios value as it seems to have no apparent affect on neither the server nor the client.

A set value is 2324.

=item * deassemble

Takes a packet recieved by either client or server and deassembles them. The returned hashref contains 
the following values:

=item * packet_type

 crc32_value
 result_code
 buffer

=item * validate($packet)

Validates the contents of a packet using CRC32 checksumming. Returns undef
if not succesful.

=back

=head1 CONSTANTS

These constants can be exported upon request with the 'use' pragma like this:

 # Will only import the constant NRPE_PACKET_VERSION_2 into your namespace
 use Nagios::NRPE::Packet qw(NRPE_PACKET_VERSION_2);

=over 2

=item * NRPE_PACKET_VERSION_3
        NRPE_PACKET_VERSION_2
        NRPE_PACKET_VERSION_1

The value of the NRPE version you want/need to use.

=item * QUERY_PACKET
        RESPONSE_PACKET

The packet type you want to send or recieve

=item * MAX_PACKETBUFFER_LENGTH
        MAX_COMMAND_ARGUMENTS

A threshhold on the send data

=item * NRPE_HELLO_COMMAND

unknown

=item * DEFAULT_SOCKET_TIMEOUT
        DEFAULT_CONNECTION_TIMEOUT

The default timeout for a connection and its corresponding socket

=item * STATE_UNKNOWN
        STATE_CRITICAL
        STATE_WARNING
        STATE_OK

States returned by the check

=back

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2013 by Andreas Marschke <andreas.marschke@googlemail.com>.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=cut

package Nagios::NRPE::Packet;

our $VERSION = '0.003';

use 5.010_000;
require Exporter;
require overload;

BEGIN {
  @ISA = qw(Exporter);
  @EXPORT_OK = qw(NRPE_PACKET_VERSION_3
                  NRPE_PACKET_VERSION_2
                  NRPE_PACKET_VERSION_1
                  NRPE_PACKET_QUERY
                  NRPE_PACKET_RESPONSE
                  MAX_PACKETBUFFER_LENGTH
                  MAX_COMMAND_ARGUMENTS
                  NRPE_HELLO_COMMAND
                  DEFAULT_SOCKET_TIMEOUT
                  DEFAULT_CONNECTION_TIMEOUT
                  STATE_UNKNOWN
                  STATE_CRITICAL
                  STATE_WARNING
                  STATE_OK);
}

use warnings;
use strict;

use Carp;
use Convert::Binary::C;
use Digest::CRC 'crc32';

use constant {
  # packet version identifier
  NRPE_PACKET_VERSION_3   =>  3,
  NRPE_PACKET_VERSION_2   =>  2,
  NRPE_PACKET_VERSION_1   =>  1,

  # id code for queries and responses to queries
  NRPE_PACKET_QUERY            =>  1,
  NRPE_PACKET_RESPONSE         =>  2,

  # max amount of data we'll send in one query/response
  MAX_PACKETBUFFER_LENGTH => 1024,
  MAX_COMMAND_ARGUMENTS   => 16,
  NRPE_HELLO_COMMAND      => "_NRPE_CHECK",
  DEFAULT_SOCKET_TIMEOUT  => 10,
  DEFAULT_CONNECTION_TIMEOUT => 300,

  # /* service state return codes */
  STATE_UNKNOWN           => 3,
  STATE_CRITICAL          => 2,
  STATE_WARNING 	  => 1,
  STATE_OK                => 0,
};

sub new {
  my ($class, %options) = @_;
  my $self = {};

# taken with modifications from common.h in nagios-nrpe
  my $c = Convert::Binary::C->new(ByteOrder => 'BigEndian', Alignment => 0);
  $c->parse(<<PACKET_STRUCT);
struct Packet{
  unsigned short   packet_version;
  unsigned short   packet_type;
  unsigned int     crc32_value;
  unsigned short   result_code;
  char             buffer[1024];
};
PACKET_STRUCT
  $c->tag('Packet.buffer', Format => 'String');
  $self->{c} = $c;
  bless $self,$class;
}

sub assemble{
  my ($self,%options) = @_;
  my $unpacked = {};
  croak "ERROR: Cannot send Packet with empty buffer!" if (not defined $options{check});

  $unpacked->{buffer}         = $options{check};
  $unpacked->{packet_version} = $options{version} || NRPE_PACKET_VERSION_2;
  $unpacked->{packet_type}    = $options{type}    || NRPE_PACKET_QUERY;
  $unpacked->{crc32_value}    = "\x00\x00\x00\x00";
  $unpacked->{result_code}    = $options{result_code}    || 2324;

  my $packed = $self->{c}->pack('Packet',$unpacked);

  $unpacked->{crc32_value} =  crc32($packed);
  $packed = $self->{c}->pack('Packet',$unpacked);
  return $packed;

}

sub validate {
  my ($self,$packet) = @_;
  my $unpacked = $self->{c}->unpack('Packet',$packet);
  my $checksum = $unpacked->{crc32_value};
  $unpacked->{crc32_value} = "\x00\x00\x00\x00";
  my $packed = $self->{c}->pack('Packet',$unpacked);
  if (crc32($packed) != $checksum) {
    return undef;
  }else {
    return 1;
  }
}

sub deassemble{
  my ($self,$packet) = @_;
  my $unpacked = $self->{c}->unpack('Packet',$packet);
  return $unpacked;
}


=pod

=over

=item packet_dump

Debugging function for hexdumping a binary string.

=back

=cut

sub packet_dump
  {
    my $packet = shift;
    my $i;
    my $k;
    my $dump;  
    my $l;
    my $ascii;
    my $c;
    for ( $i = 0; $i < length ( $packet ); $i+=16 ) {
      $l = $i+16;
      if ( $l > length ( $packet) ) {
        $l = length($packet);
      }
      $dump   = sprintf ( "%04d - %04d: ", $i, $l );
      $ascii  = "";
      for ( $k = $i; $k < $l; $k++ ) {
        $c     = ( ord ( substr ( $packet, $k, 1 ) ) );
        $dump .= sprintf ( "%02x ", $c );
        if (( $c >= 32 ) && ( $c <= 126 )) {
          $ascii .= chr ( $c );
        } else {
          $ascii .= ".";
        } 
      }
      for ( $k = 0; $k < ( $i + 16 - $l ); $k++ ) {
        $dump .= "   ";
      }
      print ( "packet_dump() ".$dump." [".$ascii."]"."\n"); 
    }
  }

1;
