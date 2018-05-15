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

my $VERSION     = 'version 1.0 (c) crs.chin@gmain.com';

my $SOCK_PATH   = "/tmp/qlogsort2_serve.sock";
my $COMMAND_DONE = "##SUBMIT_COMMAND##";

sub main {
    my $RET;
    my $CLIENT = IO::Socket::UNIX->new(Type => SOCK_STREAM(),
                                       Peer => $SOCK_PATH);

    if(! defined $ARGV[0]) {
        print "ERROR";
        return -1;
    }

    if(! $CLIENT) {
        return -1;
    }

    foreach my $argv (@ARGV) {
        $argv .= "\n";
        $CLIENT->print($argv);
    }
    $CLIENT->print($COMMAND_DONE);
    $CLIENT->print("\n");
    $CLIENT->flush;

    while(<$CLIENT>) {
        chomp;
        if($_ eq "OK") {
            $RET = 0;
            last;
        }

        if($_ eq "FAIL") {
            $RET = -1;
            last;
        }
    }

    close $CLIENT;

    return $RET;
}

exit main();

