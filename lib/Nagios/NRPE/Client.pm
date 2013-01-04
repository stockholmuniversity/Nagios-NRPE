#!/usr/bin/perl

=head1 NAME

Nagios::NRPE::Client - A Nagios NRPE client

=head1 SYNOPSIS

 use Nagios::NRPE::Client;

 my $client = Nagios::NRPE::Client->new( host => "localhost", check => 'check_cpu');
 my $response = $client->run();
 if(defined $response->{error}) {
   print "ERROR: Couldn't run check ".$client->check()." because of: "$response->{reason}."\n";
 } else {
   print $response->{status}."\n";
 }

=head1 DESCRIPTION

=cut

package Nagios::NRPE::Client;

our $VERSION = '';

use 5.010_000;

use Moose;
use String::CRC32;

has 'check' => ( is => 'rw' , isa => 'Str');
has 'host' => ( is => 'rw' , isa => 'Str');




__PACKAGE__->meta->make_immutable;
no Moose;
1;
