#
# Copyright 2022 Centreon (http://www.centreon.com/)
#
# Centreon is a full-fledged industry-strength solution that meets
# the needs in IT infrastructure and application monitoring for
# service performance.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package hardware::server::sun::sfxxk::mode::environment;

use base qw(centreon::plugins::mode);

use strict;
use warnings;
use centreon::plugins::misc;

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;
    
    $options{options}->add_options(arguments => {});

    return $self;
}

sub check_options {
    my ($self, %options) = @_;
    $self->SUPER::init(%options);
}

sub run {
    my ($self, %options) = @_;

    my ($stdout) = $options{custom}->execute_command(
        command => 'showfailover',
        command_options => '-r 2>&1',
        command_path => '/opt/SUNWSMS/bin'
    );

    if ($stdout =~ /SPARE/i) {
        $self->{output}->output_add(
            severity => 'OK', 
            short_msg => "System Controller is in spare mode."
        );
        $self->{output}->display();
        $self->{output}->exit();
    } elsif ($stdout !~ /MAIN/i) {
        $self->{output}->output_add(long_msg => $stdout);
        $self->{output}->output_add(
            severity => 'UNKNOWN', 
            short_msg => "Command problems (see additional info)."
        );
        $self->{output}->display();
        $self->{output}->exit();
    }

    ($stdout) = $options{custom}->execute_command(
        command => 'showenvironment',
        command_options => '2>&1',
        command_path => '/opt/SUNWSMS/bin'
    );
    
    $self->{output}->output_add(
        severity => 'OK', 
        short_msg => "No problems detected."
    );
    if ($stdout =~ /^LOCATION(.*?)\n\n/ims) {
        #LOCATION         SENSOR           VALUE   UNIT  AGE        STATUS
        #----------       ------------     -----   ----  ------     ------
        #SCPER at SCPER1  AMB 0 Temp       27      C     30.0  sec  HIGH_WARN
        #EXB at EX0       --               --      --    --         OFF
        #CP at CP1        DMX0 Temp        39      C     29.8  sec  OK
        my @content = split(/\n/, $1);
        shift @content;
        foreach (@content) {
            next if (/^---/);
            if (/(\S+)\s*$/ && $1 !~ /^OK|OFF|PRESENCE$/) {
                my $sensor_status = $1;
                
                /^\s*(.*?)\s{2}\s*(.*?)\s{2}\s*/;
                my $location = $1;
                $location = centreon::plugins::misc::trim($location);
                my $sensor = $2;
                $sensor = centreon::plugins::misc::trim($sensor);
            
                $self->{output}->output_add(
                    severity => 'CRITICAL', 
                    short_msg => "Sensor '$location/$sensor' status is '" . $sensor_status . "'"
                );
            }
        }
    }

    if ($stdout =~ /^FANTRAY(.*?)\n\n/ims) {
        #FANTRAY   POWER    SPEED     FAN0  FAN1  FAN2  FAN3  FAN4  FAN5
        #------    ------   -----     ----  ----  ----  ----  ----  ----
        #FT0       ON       NORMAL    OK    OK    OK    OK    OK    OK
        #FT1       ON       NORMAL    OK    OK    OK    OK    OK    OK
        my @content = split(/\n/, $1);
        shift @content;
        foreach my $line (@content) {
            
            next if ($line =~ /^---/);
            my $save_line = $line;
            $line =~ s/^\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*//;
            $save_line =~ /^\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*/;
            my $fantray = $1;
            my $fanspeed = $3;
            
            if ($fanspeed !~ /^NORMAL$/i) {
                $self->{output}->output_add(
                    severity => 'CRITICAL', 
                    short_msg => "FanTray '$fantray' speed status is '" . $fanspeed . "'"
                );
            }
            
            my $fan_num = 0;
            while ($line =~ /\s*(.+?)(\s{2}|$)/ig) {
                my $status = $1;
                $status = centreon::plugins::misc::trim($1);
                
                next if ($status eq '');
               
                if ($status !~ /^OK$/i) {
                    $self->{output}->output_add(
                        severity => 'CRITICAL', 
                        short_msg => "FanTray '$fantray' fan '$fan_num' status is '" . $status . "'"
                    );
                }
                $fan_num++;
            }
        }
    }
    
    if ($stdout =~ /^POWER\s*UNIT(.*?)\n\n/ims) {
        #POWER           UNIT     AC0      AC1      DC0      DC1      FAN0     FAN1
        #-----           ----     ---      ---      ---      ---      ----     ----
        #PS-A196 at PS0  FAIL     FAIL     FAIL     ON       ON       OK       OK
        #PS-A196 at PS1  OK       FAIL     OK       ON       ON       OK       OK
        my @content = split(/\n/, $1);
        shift @content;
        foreach my $line (@content) {
            
            next if ($line =~ /^---/);
            next if ($line !~ /^\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)\s{2}\s*(.*?)(\s{2}|$)/);
            my ($power_name, $unit, $ac0, $ac1, $dc0, $dc1, $fan0, $fan1) = ($1, $2, $3, $4, $5, $6, $7, $8);
            my $errors = '';
            $errors .= ' [UNIT=' . centreon::plugins::misc::trim($unit) . ']' if ($unit !~ /OK/i);
            $errors .= ' [AC0=' . centreon::plugins::misc::trim($ac0) . ']' if ($ac0 !~ /OK/i);
            $errors .= ' [AC1=' . centreon::plugins::misc::trim($ac1) . ']' if ($ac1 !~ /OK/i);
            $errors .= ' [DC0=' . centreon::plugins::misc::trim($dc0) . ']' if ($dc0 !~ /ON/i);
            $errors .= ' [DC1=' . centreon::plugins::misc::trim($dc1) . ']' if ($dc1 !~ /ON/i);
            $errors .= ' [DC1=' . centreon::plugins::misc::trim($fan0) . ']' if ($fan0 !~ /OK/i);
            $errors .= ' [DC1=' . centreon::plugins::misc::trim($fan1) . ']' if ($fan1 !~ /OK/i);
            if ($errors ne '') {
                $self->{output}->output_add(
                    severity => 'CRITICAL', 
                    short_msg => "Some errors on power '$power_name':" . $errors
                );
            }
        }
    }
    
    #POWER           VALUE     UNIT    STATUS
    #---------       -----     ----    ------
    #PS-A196 at PS0
    # Current0       0.00      A       N/A
    # Current1       0.00      A       N/A
    # 48VDC          0.20      V       N/A
    # Power          0.00      W       N/A
    #PS-A196 at PS1
    # Current0       0.00      A       N/A
    # Current1       14.00     A       N/A
    # 48VDC          49.60     V       N/A
    # Power          694.40    W       N/A
    #Total Power     2427.44   W       N/A
    #
    # Not managed. Dont know if there is a status???
 
    $self->{output}->display();
    $self->{output}->exit();
}

1;

__END__

=head1 MODE

Check Sun 'sfxxk' environment.

=over 8

=back

=cut
