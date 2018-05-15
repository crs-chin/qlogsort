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

qlogsort2.pl - Sort and filter Android log more decently for analysis

=head1 SYNOPSIS

qlogsort.pl - [OPTIONS] [ANDROID LOG FILE LIST]

=head1 OPTIONS

=over 4

=item B<-tag=REGEX>

Specify REGEX to match log tag against each log line, use it multiple
times to specify multiple tag, "default" is a special tag, when no
matching tag found, the "default" tag handler will be walked if
available

=item B<-handler=HANDLER>

Specify the handler for the previously specified tag, default handler
will be used if not specified

=item B<-filter=REGEX>

Specify REGEX as filter to the previously specified tag, use it
multiple times multiple REFEX matching required

=item B<-trans=REGEX>

Specify REGEX as transform regex to the previously specified tag, the
final log content will be replaced with the captured value in the
REGEX

=item B<-subs=REGEX AND PATTERN>

Specify REGEX as substitution regex to the previously specified tag,
the matching REGEX will be replaced with the next pattern specified by
-sub, eg. use the follow arguments the replace XX into YYXXYY

    -subs=(XX) -subs=YY$1YY

the "XX" is enclosed in parenthesis is to be captured by "$1" in the next
pattern, note, this arguments must come in pairs.

=item B<-handler-list>

List available handlers which can be specified in the -handler
argument

=item B<-out=FILE>

Specify the file write the final filtered log, STDOUT used if not
specified

=item B<-field>

Specify the field list to print in the final output file

=item B<-field-list>

List available field, use "all" to enable all fields output

=item B<-dissect-qmi>

Dissect QMI messages if available, using this options must have
Qualcomm QCAT application installed and available to this program

=item B<-condense-qmi=[0|1|2]>

Condense qmi message from QCAT, this options removes many redundant
information from the output of QCAT

=item B<-sort>

Sort chronologically in time stamp order if there are multiple input
files specified, Note, this could consume a lot of memory and and cpu
resource if input files are large enough

=item B<-ascend>

Sort in ascend(default) order or not

=item B<-version>

Show version of the program

=item B<-help>

Print this help message

=item B<-man>

Show manual of this executable

=back

=head1 DESCRIPTION

B<This program> will read input file(s) and parse as Android logs, and
 sort, filter in a friendly way for analyzing, eliminate junk or
 unnecessary logs from interfering.

=head1 NDROID LOG FILE LIST

File list of standard Android logs, read from stdin of no file
specified

=head1 REGEX

The REGEX is standard perl regex, eg: '/(\d+)/' to match and capture
decimal digits

=cut

my $VERSION = 'version 1.0 (c) crs.chin@gmain.com';

# configured tag handlers table
my %TAG_HANDLER_CONFIG_TABLE = (
    #########################################
    # # sample config:                      #
    # "default"       =>      {             #
    #     "handler"   =>      \&handle_tag, #
    #     "filter"    =>      [],           #
    #     "trans"     =>      [],           #
    #     "subs"      =>      [],           #
    # },                                    #
    # ".*"       =>      {                  #
    #     "handler"   =>      \&handle_qmi, #
    #     "filter"    =>      [],           #
    #     "trans"     =>      [],           #
    #     "subs"      =>      [],           #
    # },                                    #
    #########################################

    # <TAG1_REGEX>     =>  \%TAG_HANDLER_CONFIG,
    # <TAG1_REGEX>     =>  \%TAG_HANDLER_CONFIG,
    # ...
    # %TAG_HANDLER_CONFIG = (
    #     "handler"     =>      \&handle_qmi,
    #     "filter"      =>      [],
    #     "trans"       =>      [],
    #     "subs"        =>      [],
    # );
);

# supported tag handlers
my %TAG_HANDLER_TABLE = (
    "qmi"       =>  \&handle_qmi,
    "default"   =>  \&handle_tag,
);

my $OPT_LAST_TAG    = "";
my %OPT_FIELD       = (
    date    =>  0,
    time    =>  0,
    pid     =>  0,
    tid     =>  0,
    level   =>  0,
    tag     =>  0,
    message =>  0,
);

my @INPUT_STREAMS   = (
    # struct in follow:
    # {
    #     "name"  =>  "STDIN",
    #     "fd"    =>  *STDIN,
    #     "eof"   =>  0,
    # },
);
my $OUTPUT_STREAM;
my $OUTPUT_SORT     = 0;
my @OUTPUT_QUEUE    = ();

sub submit_header {
    my ($cmd_line) = @_;
    my $title = sprintf("%*s%s%*s%*s%s%*s%*s%*s%s%s\n",
                        $OPT_FIELD{"date"} ? 5 : 0,
                        $OPT_FIELD{"date"} ? "DATE" : "",
                        $OPT_FIELD{"date"} && $OPT_FIELD{"time"} ? "/" : "",
                        $OPT_FIELD{"time"} ? -12 : 0,
                        $OPT_FIELD{"time"} ? "TIME" : "",
                        $OPT_FIELD{"pid"} ? 7 : 0,
                        $OPT_FIELD{"pid"} ? "PID" : "",
                        $OPT_FIELD{"pid"} && $OPT_FIELD{"tid"} ? "/" : "",
                        $OPT_FIELD{"tid"} ? -5 : 0,
                        $OPT_FIELD{"tid"} ? "TID" : "",
                        $OPT_FIELD{"level"} ? 4 : 0,
                        $OPT_FIELD{"level"} ? "LVL" : "",
                        $OPT_FIELD{"tag"} ? 6 : 0,
                        $OPT_FIELD{"tag"} ? "TAG" : "",
                        $OPT_FIELD{"message"} ? "    " : "",
                        $OPT_FIELD{"message"} ? "MESSAGE" : "");

    print $OUTPUT_STREAM "=======================FILTERED WITH CMD LINE=======================\n";
    print $OUTPUT_STREAM "$cmd_line\n";
    print $OUTPUT_STREAM "====================================================================\n";
    print $OUTPUT_STREAM "$title";
    print $OUTPUT_STREAM "--------------------------------------------------------------------\n";
}

sub submit_line {
    my ($line) = @_;
    my $format;

    if($line->{"type"} eq "log") {
        $format = sprintf("%s%s%s %*s%s%*s %.1s %s %s\n",
                          $OPT_FIELD{"date"} ? $line->{"date"} : "",
                          $OPT_FIELD{"date"} && $OPT_FIELD{"time"} ? "/" : "",
                          $OPT_FIELD{"time"} ? $line->{"time"} : "",
                          $OPT_FIELD{"pid"} ? 6 : 0,
                          $OPT_FIELD{"pid"} ? $line->{"pid"} : "",
                          $OPT_FIELD{"pid"} && $OPT_FIELD{"tid"} ? "/" : "",
                          $OPT_FIELD{"tid"} ? -6 : 0,
                          $OPT_FIELD{"tid"} ? $line->{"tid"} : "",
                          $OPT_FIELD{"level"} ? $line->{"level"} : "",
                          $OPT_FIELD{"tag"} ? $line->{"tag"} : "",
                          $OPT_FIELD{"message"} ? $line->{"log"} : "");
    } elsif($line->{"type"} eq "qmi") {
        $format = sprintf("|          %s\n",
                          $OPT_FIELD{"message"} ? $line->{"log"} : "");
    } else {
        return;
    }

    print $OUTPUT_STREAM  "$format";
}

sub do_submit_block {
    my ($block) = @_;

    for my $line (@$block) {
        submit_line($line);
    }
}

sub flush_output_queue {
    my ($ascend) = @_;
    my $block;

    if($ascend) {
        while(@OUTPUT_QUEUE) {
            do_submit_block(shift @OUTPUT_QUEUE);
        }
        return;
    }

    while(@OUTPUT_QUEUE) {
        do_submit_block(pop @OUTPUT_QUEUE);
    }
}

sub cmp_log {
    my ($a, $b) = @_;

    return ($a->{"date"} cmp $b->{"date"}) || ($a->{"time"} cmp $b->{"time"});

    # return ($a->{"date"} cmp $b->{"date"}) if ($a->{"date"} ne $b->{"date"});
    # return ($a->{"time"} cmp $b->{"time"}) if ($a->{"time"} ne $b->{"time"});

    # if($a->{"date"} cmp $b->{"date"}) {
    #     my ($m1, $d1) = ($a->{"date"} =~ /(\d+)-(\d+)/);
    #     my ($m2, $d2) = ($b->{"date"} =~ /(\d+)-(\d+)/);

    #     return ($m1 - $m2) if ($m1 != $m2);
    #     return ($d1 - $d2) if ($d1 != $d2);
    # }

    # if($a->{"time"} cmp $b->{"time"}) {
    #     my ($h1, $m1, $s1, $f1) = ($a->{"time"} =~ /(\d+):(\d+):(\d+)\.(\d+)/);
    #     my ($h2, $m2, $s2, $f2) = ($b->{"time"} =~ /(\d+):(\d+):(\d+)\.(\d+)/);

    #     return ($h1 - $h2) if ($h1 != $h2);
    #     return ($m1 - $m2) if ($m1 != $m2);
    #     return ($s1 - $s2) if ($s1 != $s2);
    #     return ($f1 - $f2) if ($f1 != $f2);
    # }

    # return 0;
}

sub cmp_block {
    my ($a, $b) = @_;

    if(! defined $a) {
        if(defined $b) {
            return -1;
        }
        return 0;
    } elsif(! defined $b) {
        return 1;
    } else {
        return cmp_log($a->[0], $b->[0]);
    }
}

sub queue_find_pos {
    my ($block) = @_;
    my $h = @OUTPUT_QUEUE;
    my $l = 0;
    my $pos;

    return 0 if $h == 0;

    use integer;
    while($h > $l) {
        $pos = ($h + $l) / 2;
        if(cmp_block($block, $OUTPUT_QUEUE[$pos]) <= 0) {
            $h = $pos;
        } else {
            $l = $pos + 1;
        }
    }

    return $l;
}

sub queue_block {
    my ($block) = @_;
    my $pos;

    if(! $OUTPUT_SORT) {
        do_submit_block($block);
        return;
    }

    $pos = queue_find_pos($block);
    splice @OUTPUT_QUEUE, $pos, 0, $block;
}

sub submit_block {
    my ($_block, $_filter, $_trans, $_subs) = @_;
    my @block   = @$_block;
    my @filter  = @$_filter if (defined $_filter);
    my @trans   = @$_trans if (defined $_trans);
    my @subs    = @$_subs if (defined $_subs);

    my @final_block = ();

    my $filtered = 0;

    if(@block > 0) {
        for my $line (@block) {
            $filtered = 0;

            if(@filter > 0) {
                $filtered = 1;

                for my $f (@filter) {
                    if($line->{"log"} =~ $f) {
                        $filtered = 0;
                        last;
                    }
                }
            }

            if(! $filtered &&  @trans > 0) {
                my @t_out = ();

                for my $t (@trans) {
                    @t_out = ($line->{"log"} =~ $t);

                    if(@t_out > 0) {
                        my $log = "";

                        for my $c (@t_out) {
                            if($log ne "") {
                                $log .= " ";
                            }
                            $log .= $c;
                        }

                        $line->{"log"} = $log;
                    }
                }
            }

            if(! $filtered && @subs > 0) {
                my $search;
                my $replace;

                for(my $i = 0; $i < @subs; $i += 2) {
                    $search = $subs[$i];
                    $replace = $subs[$i + 1];

                    $replace =~ s/"/\\"/g;
                    $replace = '"' . $replace . '"';

                    $line->{"log"} =~ s/$search/$replace/gee;
                }
            }

            if(! $filtered) {
                push @final_block, $line;
            }
        }

        if(@final_block > 0) {
            queue_block(\@final_block);
        }
    }
}

################## qmi handling ######################
my %QMI_BLOCKS = (
    # structure as following
    # <tid1> => [ \@line1, \@line2, ... ],
    # <tid2> => [ \@line1, \@line2, ... ],
    # ...
);

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
        print STDERR "ERROR: Unable to initialize QCAT, disabling QMI dissection!\n";
    }
}

sub append_dissected_qmi_line {
    my ($lines, $message) = @_;

    push @$lines, {
        type    =>  "qmi",
        log     =>  $message,
    };
}

# Dissected QMI looks like the following, append only efective lines to
# the final text.
# 
# %MOBILE PARSED MESSAGE FILE
# %QCAT VERSION   : QCAT 06.30.50
# %SILK VERSION   : SILK_9.82
# %LOG FILE NAME  : /home/chin/tmp/111/qmi.dlf

# 1980 Jan  6  00:00:00.000  [00]  0x1544  QMI_MCS_QCSI_PKT
# packetVersion = 2
# MsgType = Response
# Counter = 2418
# ServiceId = 3
# MajorRev = 1
# MinorRev = 146
# ConHandle = 0x00000000
# MsgId = 0x0000004D
# QmiLength = 142
# Service_NAS {
#    ServiceNASV1 {
#       nas_get_sys_info {
#          nas_get_sys_info_respTlvs[0] {

sub append_dissected_qmi {
    my ($lines, $fd) = @_;

    if(! $CONDENSE_QMI) {
        while(<$fd>) {
            if($_ =~ /0x1544\s*QMI_MCS_QCSI_PKT/) {
                last;
            }
        }

        while(<$fd>) {
            chomp;
            append_dissected_qmi_line($lines, $_);
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
                    append_dissected_qmi_line($lines, $_);
                }
            }
        }
    }while(<$fd>);
}

sub dissect_qmi {
    my ($lines) = @_;
    my $header = $lines->[0];
    my $tmpfs = "/dev/shm";

    use integer;
    # don't dissect if there's no qmi body
    if(@$lines > 0) {
        my $ver         = 2;    # currently, only version 2 supported
        my $ctrl_flag   = 0;
        my $major       = 1;
        my $minor       = 146;
        my $con_handle  = 0;
        my $dummy       = "44150000000000000000";
        my ($msg_len, $srv_id, $msg_id, $tx_id, $msg_type) = (
            $lines->[0]->{"log"}
            =~
            /.*QMI_Msg Len:\s*\[(\d+)\].*\s*Serv_ID:\s*\[\w+\(0x([0-9a-fA-F]+)\)\].*\s*Msg_ID:\s*\[\w+\(0x([0-9a-fA-F]+)\)\].*Trans_ID:\s*\[(\d+)\]\s*\[(Request|Response|Indication)\]/
            );
        my $msg_body;
        my $total_len;
        my $packet;

        if(! $msg_len || ! $srv_id || ! $msg_id || ! $tx_id || ! $msg_type) {
            return;
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
            append_dissected_qmi_line($lines, "DISSECT_QMI:Unrecognized message type \"$msg_type\"");
            return;
        }

        if($srv_id == 9) {       # change major to 2 for service voice(0x9)
            $major = 2;
        }

        for(my $i = 1; $i < @$lines; ++$i) {
            my $line = $lines->[$i]->{"log"};

            $line =~ s/\s+//g;
            $msg_body .= $line;
        }

        if($msg_len != length($msg_body) / 2) {
            append_dissected_qmi_line($lines, "DISSECT_QMI:Bad qmi, length mis-match!");
            return;
        }

        # total(2) + dummy(10) + (ver(1) + ctrl_flag(1) + tx_id(2) +
        # srv_id(4) + major(4) + minor(4) + con_handle(4) + msg_id(4)
        # + msg_len(4) = 40
        $total_len = 40 + length($msg_body) / 2;

        $packet = pack 'v', $total_len;
        $packet .= pack 'H*', $dummy;
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
            append_dissected_qmi_line($lines, "DISSECT_QMI:Unable to initialize temp file to dissect qmi!");
            return;
        }

        binmode $DISSECT_INPUT_FILE_HANDLE;
        print $DISSECT_INPUT_FILE_HANDLE $packet;

        # need to close first before qcat open it
        close $DISSECT_INPUT_FILE_HANDLE;
        close $DISSECT_OUTPUT_FILE_HANDLE;

        if(! $QCAT_APP->Process($DISSECT_INPUT_FILE_NAME, $DISSECT_OUTPUT_FILE_NAME, 0, 1)) {
            my $err = $QCAT_APP->LastError();
            append_dissected_qmi_line($lines, $err);
        }

        if(! open($DISSECT_OUTPUT_FILE_HANDLE, '<', $DISSECT_OUTPUT_FILE_NAME)) {
            append_dissected_qmi_line($lines, "DISSECT_QMI:Failed to open file to read qmi!");
            return;
        }

        append_dissected_qmi($lines, $DISSECT_OUTPUT_FILE_HANDLE);

        close $DISSECT_OUTPUT_FILE_HANDLE;

        unlink $DISSECT_INPUT_FILE_NAME;
        unlink $DISSECT_OUTPUT_FILE_NAME;
    }
}

sub flush_qmi_block {
    my ($_lines, $config) = @_;
    my $_filter = $config->{"filter"};
    my $_trans  = $config->{"trans"};
    my $_subs   = $config->{"subs"};

    my @filter  = @$_filter;
    my @trans   = @$_trans;
    my @subs    = @$_subs if (defined $_subs);
    my @lines   = @$_lines;

    my $filtered = 0;

    if(@lines > 0) {
        my $_l = $lines[0];
        my %l = %$_l;

        # qmi has non-default filter handling
        if(@filter > 0) {
            $filtered = 1;

            for my $f (@filter) {
                if($l{"log"} =~ $f) {
                    $filtered = 0;
                    last;
                }
            }
        }

        if(! $filtered && $QCAT_APP) {
            dissect_qmi(\@lines);
        }

        # qmi has non-default trans handling
        if(! $filtered && @trans > 0) {
            my $log = "";
            my @t_out = ();

            for my $t (@trans) {
                @t_out = ($l{"log"} =~ $t);

                if(@t_out > 0) {
                    for my $c (@t_out) {
                        if($log ne "") {
                            $log .= " ";
                        }
                        $log .= $c;
                    }
                }
            }

            $_l->{"log"} = $log;
        }

        if(! $filtered && @subs > 0) {
            my $search;
            my $replace;

            for(my $i = 0; $i < @subs; $i += 2) {
                $search = $subs[$i];
                $replace = $subs[$i + 1];

                $replace =~ s/"/\\"/g;
                $replace = '"' . $replace . '"';

                $_l->{"log"} =~ s/$search/$replace/gee;
            }
        }

        if(! $filtered) {
            submit_block(\@lines, undef, undef, undef);
        }
    }
}

sub handle_qmi {
    my ($_line, $_config) = @_;
    my %line    =   %$_line if (defined $_line);

    # all input steam finished
    if (! defined $_line) {
        for my $i (keys %QMI_BLOCKS) {
            flush_qmi_block($QMI_BLOCKS{$i}, $_config);
            delete $QMI_BLOCKS{$i};
        }
        return;
    }

    # not QMI log, verify end of qmi msg
    if($line{"tag"} !~ /QMI_FW/) {
        if (exists $QMI_BLOCKS{$line{"tid"}}) {
            flush_qmi_block($QMI_BLOCKS{$line{"tid"}}, $_config);
            delete $QMI_BLOCKS{$line{"tid"}};
        }
        return;
    }

    # new qmi msg
    if($line{"log"} !~ /^\d+.*/) {
        if (exists $QMI_BLOCKS{$line{"tid"}}) {
            flush_qmi_block($QMI_BLOCKS{$line{"tid"}}, $_config);
            delete $QMI_BLOCKS{$line{"tid"}};
        }

        push @{ $QMI_BLOCKS{$line{"tid"}} }, \%line;
        return;
    }

    # end of qmi msg
    my @bytes = split /\s+/, $line{"log"};
    if(@bytes < 32) {
        push @{ $QMI_BLOCKS{$line{"tid"}} }, \%line;

        flush_qmi_block($QMI_BLOCKS{$line{"tid"}}, $_config);
        delete $QMI_BLOCKS{$line{"tid"}};
        return;
    }

    # middle of qmi msg
    push @{ $QMI_BLOCKS{$line{"tid"}} }, \%line;
}


################## default handling ######################
sub handle_tag {
    my ($_line, $config) = @_;
    my %line = %$_line if (defined $_line);

    if(defined $_line) {
        submit_block([ \%line ],
                     $config->{"filter"},
                     $config->{"trans"},
                     $config->{"subs"});
    }
}


# sample: 05-04 14:09:48.510   888  2225 D TAG  : log content blah blah...
sub log_dissect {
    my ($_date, $_time, $_pid, $_tid, $_level, $_tag, $_log) = (
            pop =~ /^\s*(\d+-\d+)\s+(\d+:\d+:\d+\.\d+)\s+(\d+)\s+(\d+)\s+([VDIEWF])\s+([^:]+)\s*:\s*(.*)$/
        );

    return (type    =>  "log",
            date    =>  $_date,
            time    =>  $_time,
            pid     =>  $_pid,
            tid     =>  $_tid,
            level   =>  $_level,
            tag     =>  $_tag,
            log     =>  $_log);
}


sub on_opt_tag {
    my ($name, $value) = @_;

    if(exists $TAG_HANDLER_CONFIG_TABLE{$value}) {
        print STDERR "ERROR:Tag \"$value\" already exists, ignored!\n";
        return;
    }

    $TAG_HANDLER_CONFIG_TABLE{$value} = {
        "handler"   =>  \&handle_tag,
        "filter"    =>  [],
        "trans"     =>  [],
    };

    $OPT_LAST_TAG = $value;
}

sub on_opt_handler {
    my ($name, $value) = @_;
    my $handler = '';

    if(! $OPT_LAST_TAG) {
        print STDERR "ERROR:No specifed tag to relate handler \"$value\", abort!\n";
        exit -1;
    }

    if(! exists $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG}) {
        print STDERR "ERROR:No active tag to relate handler \"$value\", abort!\n";
        exit -1;
    }

    for my $h (keys %TAG_HANDLER_TABLE) {
        if($value eq $h) {
            $handler = $TAG_HANDLER_TABLE{$h};
            last;
        }
    }

    if(! $handler) {
        print STDERR "ERROR:Unknown or not supported hander \"$value\", abort!\n";
        exit -1;
    }

    my $config = $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG};
    $config->{"handler"} = $handler;
}

sub on_opt_filter {
    my ($name, $value) = @_;

    if(! $OPT_LAST_TAG) {
        print STDERR "ERROR:No specifed tag to relate filter \"$value\", abort!\n";
        exit -1;
    }

    if(! exists $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG}) {
        print STDERR "ERROR:No active tag to relate filter \"$value\", abort!\n";
        exit -1;
    }

    my $config = $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG};
    push @{ $config->{"filter"} }, $value;
}

sub on_opt_trans {
    my ($name, $value) = @_;

    if(! $OPT_LAST_TAG) {
        print STDERR "ERROR:No specifed tag to relate trans \"$value\", abort!\n";
        exit -1;
    }

    if(! exists $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG}) {
        print STDERR "ERROR:No active tag to relate trans \"$value\", abort!\n";
        exit -1;
    }

    my $config = $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG};
    push @{ $config->{"trans"} }, $value;
}

sub on_opt_subs {
    my ($name, $value) = @_;

    if(! $OPT_LAST_TAG) {
        print STDERR "ERROR:No specifed tag to relate trans \"$value\", abort!\n";
        exit -1;
    }

    if(! exists $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG}) {
        print STDERR "ERROR:No active tag to relate trans \"$value\", abort!\n";
        exit -1;
    }

    my $config = $TAG_HANDLER_CONFIG_TABLE{$OPT_LAST_TAG};
    push @{ $config->{"subs"} }, $value;
}

sub on_opt_handler_list {
    print "Supported tag handlers:\n";
    for my $h (keys %TAG_HANDLER_TABLE) {
        print "  $h\n";
    }
    exit 0;
}

sub on_opt_out {
    my ($name, $value) = @_;

    if(! open($OUTPUT_STREAM, '>', $value)) {
        print STDERR "ERROR: failed to open \"$value\" to write, abort!\n";
        exit -1;
    }
}

sub on_opt_field {
    my ($name, $value) = @_;
    my @fields = split /,/,$value;

    for my $f (@fields) {
        if($f eq "all") {
            foreach my $k (keys %OPT_FIELD) {
                $OPT_FIELD{$k} = 1;
            }
            next;
        }

        if(! exists $OPT_FIELD{$f}) {
            print STDERR "ERROR: Unspported field specification \"$f\", abort!\n";
            exit -1;
        }
        $OPT_FIELD{$f} = 1;
    }
}

sub on_opt_field_list {
    print "Supported field list:\n";
    for my $f (keys %OPT_FIELD) {
        print "  $f\n";
    }
    print "  all\n";
    exit 0;
}

sub on_opt_args {
    my ($name, $value) = @_;
    my $input;

    if(! open($input, '<', $name)) {
        print STDERR "ERROR: Unable to open \"$name\" to read, abort!\n";
        exit -1;
    }

    for my $in (@INPUT_STREAMS) {
        if($in->{"name"} eq $name) {
            return;
        }
    }

    push @INPUT_STREAMS, {
        "eof"   =>  0,
        "fd"    =>  $input,
        "name"  =>  $name,
    };
}

sub on_opt_version {
    my ($name, $value) = @_;

    print "$FindBin::Script $VERSION\n";
    exit 0;
}

sub main {
    my $OPT_DISSECT_QMI  = 0;
    my $OPT_CONDENSE_QMI= 0;
    my $OPT_SORT        = 0;
    my $OPT_ASCEND      = 1;
    my $OPT_HELP        = "";
    my $OPT_MAN         = "";
    my $CMD_LINE        = $FindBin::Script;

    for my $i (@ARGV) {
        if($CMD_LINE) {
            $CMD_LINE .= " ";
        }

        $CMD_LINE .= "\""  if($i !~ /-.*/);
        $CMD_LINE .= $i;
        $CMD_LINE .= "\""  if($i !~ /-.*/);;
    }

    GetOptions("tag=s@",        =>  \&on_opt_tag,
               "handler=s@"     =>  \&on_opt_handler,
               "filter=s@"      =>  \&on_opt_filter,
               "trans=s@"       =>  \&on_opt_trans,
               "subs=s@"        =>  \&on_opt_subs,
               "handler-list"   =>  \&on_opt_handler_list,
               "out=s"          =>  \&on_opt_out,
               "field=s"        =>  \&on_opt_field,
               "field-list"     =>  \&on_opt_field_list,
               "<>"             =>  \&on_opt_args,
               "version"        =>  \&on_opt_version,
               "dissect-qmi"    =>  \$OPT_DISSECT_QMI,
               "condense-qmi=i" =>  \$OPT_CONDENSE_QMI,
               "sort!"          =>  \$OPT_SORT,
               "ascend"         =>  \$OPT_ASCEND,
               "help"           =>  \$OPT_HELP,
               "man"            =>  \$OPT_MAN)
        or
        pod2usage(-verbose => 1);

    pod2usage(-verbose => 1) if $OPT_HELP;
    pod2usage(-verbose => 2) if $OPT_MAN;

    foreach my $key (keys %TAG_HANDLER_CONFIG_TABLE) {
        my $config = $TAG_HANDLER_CONFIG_TABLE{$key};
        my $_subs = $config->{"subs"};
        my @subs = @$_subs if (defined $_subs);

        if(@subs % 2) {
            print STDERR "ERROR:Substitution arguments must come in pairs, abort!\n";
            exit -1;
        }
    }

    if($OPT_DISSECT_QMI) {
        qcat_init();
    }

    if($OPT_CONDENSE_QMI        &&
       $OPT_CONDENSE_QMI != 0   &&
       $OPT_CONDENSE_QMI != 1   &&
       $OPT_CONDENSE_QMI != 2) {
        print STDERR "ERROR:Error level of condensing qmi \"$OPT_CONDENSE_QMI\", abort!\n";
        exit -1;
    }
    $CONDENSE_QMI = $OPT_CONDENSE_QMI;

    if($OPT_SORT) {
        $OUTPUT_SORT = 1;
    }

    if(@INPUT_STREAMS == 0) {
        push @INPUT_STREAMS, {                          
            "name"  =>  "STDIN",
            "fd"    =>  *STDIN,
            "eof"   =>  0,
        };
    }

    if(! defined $OUTPUT_STREAM) {
        $OUTPUT_STREAM = *STDOUT;
    }

    submit_header($CMD_LINE);

    foreach my $in (@INPUT_STREAMS) {
        my $fd = $in->{"fd"};
        my %log;

        while(<$fd>) {
            last if(! $_);

            %log = log_dissect($_);
            next if (!  $log{"tag"});

            for my $key (keys %TAG_HANDLER_CONFIG_TABLE) {
                if($log{"tag"} =~ $key) {
                    my $config = $TAG_HANDLER_CONFIG_TABLE{$key};

                    $config->{"handler"}(\%log, $config);
                }
            }
        }
    }

    # flush all tags by sending undef %log
    for my $key (keys %TAG_HANDLER_CONFIG_TABLE) {
        my $config = $TAG_HANDLER_CONFIG_TABLE{$key};
        $config->{"handler"}(undef, $config);
    }

    flush_output_queue($OPT_ASCEND);

    return 0;
}

exit main();

END {
    if($QCAT_APP) {
        $QCAT_APP->Exit();
        $QCAT_APP = 0;
    }
}

