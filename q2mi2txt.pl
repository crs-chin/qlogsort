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

BEGIN {
    push @INC, "/Applications/QCAT/QCAT/Script";
}

use strict;
use warnings;
use FindBin;
use File::Temp qw/ tempfile /;
use Getopt::Long;
use Pod::Usage;

use QCATDBus;


=pod

=head1 NAME

q2mi2txt.pl - Pure qmi dissector

=head1 SYNOPSIS

q2mi2txt.pl - [OPTIONS] [ANDROID LOG FILE LIST]

=head1 OPTIONS

=over 4

=item B<-condense-qmi=[0|1|2]>

Condense qmi message from QCAT, this options removes many redundant
information from the output of QCAT

=item B<-version>

Show version of the program

=item B<-help>

Print this help message

=item B<-man>

Show manual of this executable

=back

=cut

my $VERSION = 'version 1.0 (c) crs.chin@gmain.com';

my $QCAT_APP;
my $CONDENSE_QMI = 0;
my $DISSECT_INPUT_FILE_HANDLE;
my $DISSECT_INPUT_FILE_NAME;
my $DISSECT_OUTPUT_FILE_HANDLE;
my $DISSECT_OUTPUT_FILE_NAME;

sub qcat_init {
    return if $QCAT_APP;

    $QCAT_APP = newQCAT6Application();
    if(! $QCAT_APP) {
        print STDERR "ERROR: Unable to initialize QCAT, abort!\n";
        exit -1;
    }
}

sub qcat_finit {
    return if (! $QCAT_APP);

    $QCAT_APP->Exit();
    $QCAT_APP = 0;
}


sub append_dissected_qmi_line {
    my ($line) = @_;

    print $line,"\n";
}

sub append_dissected_qmi {
    my ($fd) = @_;

    if(! $CONDENSE_QMI) {
        while(<$fd>) {
            if($_ =~ /0x1544\s*QMI_MCS_QCSI_PKT|0x1391\s*QMI Link/) {
                last;
            }
        }

        while(<$fd>) {
            chomp;
            append_dissected_qmi_line($_);
        }
        return;
    }

    while(<$fd>) {
        if($_ =~ /^.*{$/) {
            last;
        }
    }

    do {
        if($_) {
            chomp;
            if($_ !~ /^\s*$/) {
                if($CONDENSE_QMI != 2 ||
                   $_ !~ /^\s*Type\s*=|^\s*Length\s*=|^\s*resp\s*\{$|^\s*\}$/) {
                    $_ =~ s/\s*\{|_respTlvs\[\d*\]\s*\{|_reqTlvs\[\d*\]\s*\{|_indTlvs\[\d*\]\s*\{//g;
                    append_dissected_qmi_line($_);
                }
            }
        }
    }while(<$fd>);
}

sub dissect_qmi {
    my $tmpfs = "/dev/shm";
    my $ver         = 2;    # currently, only version 2 supported
    my $ctrl_flag   = 0;
    my $major       = 1;
    my $minor       = 146;
    my $con_handle  = 0;
    my $dummy_qc_qmi= "91130000000000000000";
    my $dummy_qmi_fw= "44150000000000000000";
    my $msg_body;
    my $total_len;
    my $packet;

    use integer;

    while(<>) {
        my ($qmi_version, $msg_len, $srv_id, $msg_id, $tx_id, $msg_type) = (
            $_
            =~
            /.*(QC-QMI|QMI_FW).*QMI_Msg Len:\s*\[(\d+)\].*\s*Serv_ID:\s*\[\w+\(0x([0-9a-fA-F]+)\)\].*\s*Msg_ID:\s*\[[\w<>]+\(0x([0-9a-fA-F]+)\)\].*Trans_ID:\s*\[(\d+)\]\s*\[(Request|Response|Indication)\]/
        );

        if(! $qmi_version   ||
           ! $msg_len       ||
           ! $srv_id        ||
           ! $msg_id        ||
           ! $tx_id         ||
           ! $msg_type)
        {
            next;
        }

        $srv_id = hex($srv_id);
        $msg_id = hex($msg_id);

        if($msg_type eq "Request") {
            $ctrl_flag = 0;
        } elsif ($msg_type eq "Response" ) {
            $ctrl_flag = 1;
        } elsif ($msg_type eq "Indication") {
            $ctrl_flag = 2;
        } else {
            append_dissected_qmi_line("DISSECT_QMI:Unrecognized message type \"$msg_type\"");
            return;
        }

        if($srv_id == 9) {       # change major to 2 for service voice(0x9)
            $major = 2;
        }

        while(<>) {
            $_ =~ s/.*://;
            $_ =~ s/\s+//g;
            $msg_body .= $_;
        }

        if($msg_len != length($msg_body) / 2) {
            append_dissected_qmi_line("DISSECT_QMI:Bad qmi, length mis-match!");
            return;
        }

        if($qmi_version eq "QC-QMI") {
            # total(2) + dummy(10) = 12
            $total_len = 12 + length($msg_body) / 2;

            $packet  = pack 'v', $total_len;
            $packet .= pack 'H*', $dummy_qc_qmi;
            $packet .= pack 'H*', $msg_body;
        } else {                # QMI_FW
            # total(2) + dummy(10) + (ver(1) + ctrl_flag(1) + tx_id(2) +
            # srv_id(4) + major(4) + minor(4) + con_handle(4) + msg_id(4)
            # + msg_len(4) = 40
            $total_len = 40 + length($msg_body) / 2;

            $packet  = pack 'v', $total_len;
            $packet .= pack 'H*', $dummy_qmi_fw;
            $packet .= pack 'C', $ver;
            $packet .= pack 'C', $ctrl_flag;
            $packet .= pack 'v', $tx_id;
            $packet .= pack 'V', $srv_id;
            $packet .= pack 'V', $major;
            $packet .= pack 'V', $minor;
            $packet .= pack 'V', $con_handle;
            $packet .= pack 'V', $msg_id;
            $packet .= pack 'V', $msg_len;
            $packet .= pack 'H*',$msg_body;
        }

        if( -d $tmpfs) {
            ($DISSECT_INPUT_FILE_HANDLE, $DISSECT_INPUT_FILE_NAME) = tempfile(DIR => $tmpfs, SUFFIX => ".dlf");
            ($DISSECT_OUTPUT_FILE_HANDLE, $DISSECT_OUTPUT_FILE_NAME) = tempfile(DIR => $tmpfs, SUFFIX => ".txt");
        } else {
            ($DISSECT_INPUT_FILE_HANDLE, $DISSECT_INPUT_FILE_NAME) = tempfile(SUFFIX => ".dlf");
            ($DISSECT_OUTPUT_FILE_HANDLE, $DISSECT_OUTPUT_FILE_NAME) = tempfile(SUFFIX => ".txt");
        }

        if(! $DISSECT_INPUT_FILE_HANDLE ||
           ! $DISSECT_INPUT_FILE_NAME   ||
           ! $DISSECT_OUTPUT_FILE_HANDLE||
           ! $DISSECT_OUTPUT_FILE_NAME) {
            append_dissected_qmi_line("DISSECT_QMI:Unable to initialize temp file to dissect qmi!");
            return;
        }

        binmode $DISSECT_INPUT_FILE_HANDLE;
        print $DISSECT_INPUT_FILE_HANDLE $packet;

        # need to close first before qcat open it
        close $DISSECT_INPUT_FILE_HANDLE;
        close $DISSECT_OUTPUT_FILE_HANDLE;

        do{
            if(! $QCAT_APP->Process($DISSECT_INPUT_FILE_NAME, $DISSECT_OUTPUT_FILE_NAME, 0, 1)) {
                my $err = $QCAT_APP->LastError();
                append_dissected_qmi_line($err);
                last;
            }

            if(! open($DISSECT_OUTPUT_FILE_HANDLE, '<', $DISSECT_OUTPUT_FILE_NAME)) {
                append_dissected_qmi_line("DISSECT_QMI:Failed to open file to read qmi!");
                last;
            }

            append_dissected_qmi($DISSECT_OUTPUT_FILE_HANDLE);

            close $DISSECT_OUTPUT_FILE_HANDLE;
        }while(0);

        unlink $DISSECT_INPUT_FILE_NAME;
        unlink $DISSECT_OUTPUT_FILE_NAME;

        last;
    }
}

sub on_opt_version {
    my ($name, $value) = @_;

    print "$FindBin::Script $VERSION\n";
    exit 0;
}

sub main {
    my $OPT_CONDENSE_QMI= 0;
    my $OPT_HELP        = "";
    my $OPT_MAN         = "";

    GetOptions("version"        =>  \&on_opt_version,
               "condense-qmi=i" =>  \$OPT_CONDENSE_QMI,
               "help"           =>  \$OPT_HELP,
               "man"            =>  \$OPT_MAN)
        or
        pod2usage(-verbose => 1);

    pod2usage(-verbose => 1) if $OPT_HELP;
    pod2usage(-verbose => 2) if $OPT_MAN;

    if($OPT_CONDENSE_QMI        &&
       $OPT_CONDENSE_QMI != 0   &&
       $OPT_CONDENSE_QMI != 1   &&
       $OPT_CONDENSE_QMI != 2) {
        print STDERR "ERROR:Error level of condensing qmi \"$OPT_CONDENSE_QMI\", abort!\n";
        exit -1;
    }

    $CONDENSE_QMI = $OPT_CONDENSE_QMI;

    qcat_init();

    dissect_qmi();

    qcat_finit();

    return 0;
}

exit main();

END {
    if($QCAT_APP) {
        $QCAT_APP->Exit();
        $QCAT_APP = 0;
    }
}

