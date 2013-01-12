#!/usr/bin/perl
use 5.010_000;

use strict;
use warnings;

use Data::Dumper;
use Getopt::Long;
use IO::File;
use Pod::Usage;
use Nagios::NRPE::Daemon;
use Nagios::NRPE::Packet;
use IPC::Cmd qw(run);

my $daemon = Nagios::NRPE::Daemon->new(listen => "0.0.0.0",
				       port   => "5666",
				       pid_dir => "./",
				       ssl => 0,
				       commandlist => {
					 "check_cpu" => {
					   bin => "/usr/bin/printf",
					   args => "\"Hello World!\""
					  }
					},
				       callback => sub {
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
				       }
				      );

$daemon->start();
