#!/usr/bin/perl
#
# Copyright (C) <2018>  Crs Chin<crs.chin@gmail.com>
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#

use strict;
use warnings;
use FindBin;
use IO::Socket::UNIX;
use Getopt::Long;
use Pod::Usage;

=pod

=head1 NAME

qlogsort2_serve.pl - serve daemon to qlogsort2.pl

=head1 SYNOPSIS

qlogsort2_serve.pl - [OPTIONS]

=head1 OPTIONS

=over 4

=item B<-version>

Show version of the program

=item B<-help>

Print this help message

=item B<-man>

Show manual of this executable

=back

=cut

my $VERSION         = 'version 1.0 (c) crs.chin@gmain.com';

my $QLOGSORT2_PATH  = "/home/chin/bin/qlogsort2.pl";
my $SOCK_PATH       = "/tmp/qlogsort2_serve.sock";

my $COMMAND_DONE    = "##SUBMIT_COMMAND##";

sub handle_session {
    my ($conn) = @_;
    my @cmd_to_exec = ( $QLOGSORT2_PATH );
    my $ret;

    print "MSG: NEW CONNECTION\n";
    while(<$conn>) {
        chomp;

        if($_ eq $COMMAND_DONE) {
            print "MSG: EXEC: \"@cmd_to_exec\"\n";
            $ret = system(@cmd_to_exec);

            $conn->print($ret == 0 ? "OK\n" : "FAIL\n");
            $conn->flush;
            last;
        }

        push @cmd_to_exec, $_;
    }

    close $conn;
}

sub on_opt_args {
    my ($name, $value) = @_;

    # TODO with $name
}

sub on_opt_version {
    my ($name, $value) = @_;

    print "$FindBin::Script $VERSION\n";
    exit 0;
}

sub main {
    my $OPT_HELP        = "";
    my $OPT_MAN         = "";

    GetOptions("path=s"     =>  \$QLOGSORT2_PATH,
               "help"       =>  \$OPT_HELP,
               "man"        =>  \$OPT_MAN)
        or
        pod2usage(-verbose => 1);

    pod2usage(-verbose => 1) if $OPT_HELP;
    pod2usage(-verbose => 2) if $OPT_MAN;


    if(! -f $QLOGSORT2_PATH) {
        print STDERR "ERROR:\"$QLOGSORT2_PATH\" not available, abort\n";
        return -1;
    }


    unlink $SOCK_PATH if (-e $SOCK_PATH);

    my $SERVER = IO::Socket::UNIX->new(Type     =>  SOCK_STREAM(),
                                       Local    =>  $SOCK_PATH,
                                       Listen   =>  1);

    while(my $conn = $SERVER->accept()) {
        handle_session($conn);
    }

    return 0;
}

exit main();

END {
    unlink $SOCK_PATH;
}
