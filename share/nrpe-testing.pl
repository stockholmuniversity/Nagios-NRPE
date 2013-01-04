#!/usr/bin/perl
use 5.010_000;

use strict;
use warnings;

use Data::Dumper;
use String::CRC32;
use IO::Socket;
use IO::Socket::INET;
use constant {
  # packet version identifier
  NRPE_PACKET_VERSION_3   =>  3,
  NRPE_PACKET_VERSION_2   =>  2,
  NRPE_PACKET_VERSION_1   =>  1,

  # id code for queries and responses to queries
  QUERY_PACKET            =>  1,
  RESPONSE_PACKET         =>  2,
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
  STATE_OK                => 0
};
my ($packet_version,  # Version of NRPE
    $packet_type,     # Clients = QUERY = 1, Server = RESPONSE = 2
    $crc32_value,
    $result_code,     # \x00 on querys
    $buffer           # buffer text consisting of the check name and its adjacent arguments max 1024 bytes
);

my $command = "check_users";

# packet pre crc32:
$packet_version = pack('S',NRPE_PACKET_VERSION_2);
$packet_type = pack('S',QUERY_PACKET);
$crc32_value = pack('L',0);
$result_code = pack('S',0);
$buffer = pack('a[1024]',$command);

# pad buffer with \x00
for (my $i =0; $i < MAX_PACKETBUFFER_LENGTH - (length $buffer); $i++ ) {
  my $temp_buffer = unpack('A*',$buffer);
  $buffer = pack('A*',$temp_buffer,"\x00");
}

# NON CRC32 packet
my $packet = "$packet_version"."$packet_type"."$crc32_value"."$result_code"."$buffer";

$crc32_value = pack('l*',~crc32($packet));
print $crc32_value;
$packet = "\x00"."$packet_version"."$packet_type"."$crc32_value"."$result_code"."$buffer"."\x00";

# my $socket = IO::Socket::INET->new(PeerAddr => '10.0.0.47',
# 				   PeerPort => '5666',
# 				   Proto => 'tcp',
# 				   Type => SOCK_STREAM) or die "ERROR: $@ \n";

# print $socket "$packet";

# while (<$socket>) {
#   packet_dump($_);
# }

# close($socket);

=pod

Utils Section

=cut

sub packet_dump {
  my $packet = shift;
  my ($i, $k, $dump, $l, $ascii, $c);

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
    print( "packet_dump() ".$dump." [".$ascii."]\n" );
  }
}

