#!/usr/bin/perl
use 5.010_000;

use strict;
use warnings;

use Data::Dumper;
use Getopt::Long;
use IO::Socket::INET;
use Pod::Usage;
use String::CRC32;
use String::Random;

our $VERSION = '';

my ($host,$command,$port,$ssl);

my $result = GetOptions (
  "p|port=s"    => \$port,
  "H|host=s"    => \$host,
  "c|command=s" => \$command,
  "s|ssl"       => \$ssl,
  "h|help"      => sub { pod2usage(-exitval   => 0,
				   -verbose   => 99,
				   -noperldoc => 1) });

$port = 5666 unless defined $port;
$host = "localhost" unless defined $host;
$ssl = undef unless defined $ssl;
$command = "check_users" unless defined $command;



my $foo = new String::Random;
my ($packet_version, $packet_type, $crc32_value, $result_code, $buffer);


$packet_version = "512";
$packet_type = "256";
$crc32_value = "0";
$result_code = $foo->randregex('[a-z0-9]{6}');
$buffer = $command;

my $int = length($command);

for (my $i = 0; $i < 1024-$int; $i++) {
  $buffer .= "\x0";
}

my $packet = pack('S S n S A[1024]',($packet_version, $packet_type, $crc32_value, $result_code, $buffer));
$crc32_value = crc32($packet);

$packet = pack('S S n S A[1024]',($packet_version, $packet_type, $crc32_value, $result_code, $buffer));

my $socket = IO::Socket::INET->new(PeerAddr => $host,
				   PeerPort => $port,
				   Proto => "tcp",
				   Timeout => 5
				  );
$socket->print($packet);

while ($socket->getline()) {
  print unpack('S S n S A[1024]',$_)
}

$socket->close;
