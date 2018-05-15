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
use File::Temp qw/ tempfile /;
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

my $COMMAND_DONE    = "##QLOGSOR2_COMMAND_ARGUMENTS_DONE_QLOGSOR2##";
my $CONTENT_DONE    = "##QLOGSOR2_FILE_CONTENTS_DONE_QLOGSOR2##";
my $COMMAND_RES_OK  = "##QLOGSOR2_COMMAND_RESULT_OK_QLOGSOR2##";
my $COMMAND_RES_FAIL= "##QLOGSOR2_COMMAND_RESULT_FAIL_QLOGSOR2##";

sub handle_session {
    my ($conn) = @_;
    my @cmd_to_exec         = ( $QLOGSORT2_PATH );
    my ($fd_in, $file_in)   = tempfile();
    my ($fd_out, $file_out) = tempfile();
    my $cmd_recved          = 0;
    my $ret                 = 0;

    close $fd_out;

    print "MSG: NEW CONNECTION\n";
    while(<$conn>) {
        chomp;

        if(! $cmd_recved) {
            if($_ eq $COMMAND_DONE) {
                $cmd_recved = 1;
            } else {
                push @cmd_to_exec, $_;
            }
        } else {
            if($_ eq $CONTENT_DONE) {
                last
            }

            print $fd_in $_,"\n";
        }
    }

    push @cmd_to_exec, $file_in;
    push @cmd_to_exec, "-out";
    push @cmd_to_exec, $file_out;

    print "MSG: EXEC: \"@cmd_to_exec\"\n";
    $ret = system(@cmd_to_exec);

    $conn->print($ret == 0 ? $COMMAND_RES_OK : $COMMAND_RES_FAIL);
    $conn->print("\n");

    if($ret == 0) {
        if(! open($fd_out, '<', $file_out)) {
            $conn->print("ERROR:unexpected empty dissection output!\n");
            close $conn;
            return;
        }

        while(<$fd_out>) {
            $conn->print($_);
        }
        $conn->flush;
        close $fd_out;
    }

    unlink $file_in;
    unlink $file_out;

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
