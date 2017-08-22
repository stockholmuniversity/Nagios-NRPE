#!/usr/bin/perl

=pod

=head1 NAME

Nagios::NRPE::Utils - Common helper functions for Nagios::NRPE

=head1 DESCRIPTION

This file contains common helper functions for the submodules 
Nagios::NRPE::Client,  Nagios::NRPE::Packet and Nagios::NRPE::Daemon.

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2017 by the authors (see AUTHORS file).
This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.

=head1 METHODS

=over  

=item return_error

Create a hash with the specified error message using this format

{
    error => 1,
    reason => "some reason"
}

=back

=cut

package Nagios::NRPE::Utils;

use strict;
use warnings;
our $VERSION = '1.0.3';
require Exporter;

BEGIN {
    my @ISA = qw(Exporter);
    my @EXPORT_OK = qw(return_error);
}

sub return_error {
        my ($reason) = @_;
        my %return;
        $return{'error'}  = 1;
        $return{'reason'} = $reason;
        return ( \%return );

}


1;
