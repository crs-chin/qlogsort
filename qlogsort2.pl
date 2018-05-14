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
use Getopt::Long;
use Pod::Usage;

=pod

=head1 NAME

qlogsort.pl - Sort and filter Android log more decently for analysis

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
will be used if not specifed

=item B<-filter=REGEX>

Specify REGEX as filter to the previously specified tag, use it
multiple times multiple REFEX matching required

=item B<-trans=REGEX>

Specify REGEX as transform regex to the previously specified tag, the
final log content will be replaced with the capatured value in the
REGEX

=item B<-subs=REGEX AND PATTERN>

Specify REGEX as substitution regex to the previously specified tag,
the matching REGEX will be replaced with the next pattern specified by
-sub, eg. use the follow arguments the replace XX into YYXXYY

    -subs=(XX) -subs=YY$1YY

the "XX" is enclosed in parensis is to be captured by "$1" in the next
pattern, note, this arguments must come in pairs.

=item B<-handler-list>

List available handlers which can be specified in the -handler
argument

=item B<-out=FILE>

Specify the file write the final filtered log, STDOUT used if not
specified

=item B<-sort>

Sort chronologically in time stamp order if there are multiple input
files specified, Note, this could comsume a lot of memory and and cpu
resource if input files are large enough

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
    my $format = sprintf("%s%s%s %*s%s%*s %.1s %s %s\n",
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

sub flush_qmi_block {
    my ($_lines, $config) = @_;
    my $_filter = $config->{"filter"};
    my $_trans  = $config->{"trans"};
    my $_subs   = $config->{"subs"};

    my @filter  = @$_filter;
    my @trans   = @$_trans;
    my @subs    = @$_subs;
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
            # TODO: desect QMI here if supported
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
sub log_desect {
    my ($_date, $_time, $_pid, $_tid, $_level, $_tag, $_log) = (
            pop =~ /^\s*(\d+-\d+)\s+(\d+:\d+:\d+\.\d+)\s+(\d+)\s+(\d+)\s+([VDIEWF])\s+([^:]+)\s*:\s*(.*)$/
        );

    return (date    =>  $_date,
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

sub main {
    my $OPT_SORT    = 0;
    my $OPT_ASCEND  = 1;
    my $OPT_HELP    = "";
    my $OPT_MAN     = "";
    my $CMD_LINE    = $FindBin::Script;

    for my $i (@ARGV) {
        if($CMD_LINE) {
            $CMD_LINE .= " ";
        }

        $CMD_LINE .= "\""  if($i !~ /-.*/);
        $CMD_LINE .= $i;
        $CMD_LINE .= "\""  if($i !~ /-.*/);;
    }

    GetOptions("tag=s@",    =>  \&on_opt_tag,
               "handler=s@" =>  \&on_opt_handler,
               "filter=s@"  =>  \&on_opt_filter,
               "trans=s@"   =>  \&on_opt_trans,
               "subs=s@"    =>  \&on_opt_subs,
               "handler-list"   =>  \&on_opt_handler_list,
               "out=s"      =>  \&on_opt_out,
               "field=s"    =>  \&on_opt_field,
               "field-list" =>  \&on_opt_field_list,
               "<>"         =>  \&on_opt_args,
               "sort!"      =>  \$OPT_SORT,
               "ascend"     =>  \$OPT_ASCEND,
               "help"       =>  \$OPT_HELP,
               "man"        =>  \$OPT_MAN)
        or
        pod2usage(-verbose => 1);

    pod2usage(-verbose => 1) if $OPT_HELP;
    pod2usage(-verbose => 2) if $OPT_MAN;

    foreach my $key (keys %TAG_HANDLER_CONFIG_TABLE) {
        my $config = $TAG_HANDLER_CONFIG_TABLE{$key};
        my $_subs = $config->{"subs"};
        my @subs = @$_subs;

        if(@subs % 2) {
            print STDERR "ERROR:Substitution arguments must come in pairs, abort!\n";
            exit -1;
        }
    }

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

            %log = log_desect($_);
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
