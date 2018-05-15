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

my $SOCK_PATH       = "/tmp/qlogsort2_serve.sock";

my $COMMAND_DONE    = "##QLOGSOR2_COMMAND_ARGUMENTS_DONE_QLOGSOR2##";
my $CONTENT_DONE    = "##QLOGSOR2_FILE_CONTENTS_DONE_QLOGSOR2##";
my $COMMAND_RES_OK  = "##QLOGSOR2_COMMAND_RESULT_OK_QLOGSOR2##";
my $COMMAND_RES_FAIL= "##QLOGSOR2_COMMAND_RESULT_FAIL_QLOGSOR2##";

sub main {
    my @CMD_ARGUMENTS   = (
        "-tag", ".*", "-handler", "qmi", "-no-header", "-field", "all", "-dissect-qmi", "-condense-qmi", "2",
        );
    my $RET             = 0;
    my $CLIENT          = IO::Socket::UNIX->new(Type => SOCK_STREAM(),
                                                Peer => $SOCK_PATH);

    if(! $CLIENT) {
        return -1;
    }

    # send arguments
    foreach my $arg (@CMD_ARGUMENTS) {
        $CLIENT->print($arg);
        $CLIENT->print("\n");
    }
    $CLIENT->print($COMMAND_DONE);
    $CLIENT->print("\n");

    # send contents
    while(<STDIN>) {
        $CLIENT->print($_);
    }
    $CLIENT->print($CONTENT_DONE);
    $CLIENT->print("\n");

    while(<$CLIENT>) {
        chomp;
        if($_ eq $COMMAND_RES_OK) {
            $RET = 0;
            last;
        }

        if($_ eq $COMMAND_RES_FAIL) {
            $RET = -1;
            last;
        }
    }

    if($RET == 0) {
        while(<$CLIENT>) {
            print $_;
        }
    }

    close $CLIENT;

    return $RET;
}

exit main();

