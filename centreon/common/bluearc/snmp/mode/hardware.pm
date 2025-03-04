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

package centreon::common::bluearc::snmp::mode::hardware;

use base qw(centreon::plugins::templates::hardware);

use strict;
use warnings;

sub set_system {
    my ($self, %options) = @_;

    $self->{regexp_threshold_numeric_check_section_option} = '^(temperature|fan)$';

    $self->{cb_hook2} = 'snmp_execute';

    $self->{thresholds} = {
        psu => [
            ['ok', 'OK'],
            ['failed', 'CRITICAL'],
            ['notFitted', 'WARNING'],
            ['unknown', 'UNKNOWN'],
        ],
        'fan.speed' => [
            ['ok', 'OK'],
            ['warning', 'WARNING'],
            ['severe', 'CRITICAL'],
            ['unknown', 'UNKNOWN'],
        ],
        temperature => [
            ['ok', 'OK'],
            ['tempWarning', 'WARNING'],
            ['tempSevere', 'CRITICAL'],
            ['tempSensorFailed', 'CRITICAL'],
            ['tempSensorWarning', 'CRITICAL'],
            ['unknown', 'UNKNOWN'],
        ],
        sysdrive => [
            ['online', 'OK'],
            ['corrupt', 'WARNING'],
            ['failed', 'CRITICAL'],
            ['notPresent', 'OK'],
            ['disconnected', 'WARNING'],
            ['offline', 'OK'],
            ['initializing', 'OK'],
            ['formatting', 'OK'],
            ['unknown', 'UNKNOWN'],
        ],
        battery => [
            ['ok', 'OK'],
            ['fault', 'CRITICAL'],
            ['notFitted', 'WARNING'],
            ['initializing', 'OK'],
            ['normalCharging', 'OK'],
            ['discharged', 'CRITICAL'],
            ['cellTesting', 'OK'],
            ['notResponding', 'CRITICAL'],
            ['low', 'WARNING'],
            ['veryLow', 'CRITICAL'],
            ['ignore', 'UNKNOWN'],
        ],
    };

    $self->{components_path} = 'centreon::common::bluearc::snmp::mode::components';
    $self->{components_module} = ['temperature', 'fan', 'psu', 'sysdrive', 'battery' ];
}

sub snmp_execute {
    my ($self, %options) = @_;

    $self->{snmp} = $options{snmp};
    $self->{results} = $self->{snmp}->get_multiple_table(oids => $self->{request});
}

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options, no_absent => 1);
    bless $self, $class;

    $options{options}->add_options(arguments => {});

    return $self;
}

1;

__END__

=head1 MODE

Check Hardware.

=over 8

=item B<--component>

Which component to check (Default: '.*').
Can be: 'temperature', 'fan', 'psu', 'sysdrive', 'battery'.

=item B<--filter>

Exclude some parts (comma seperated list) (Example: --filter=sysdrive)
Can also exclude specific instance: --filter=sysdrive,1

=item B<--no-component>

Return an error if no compenents are checked.
If total (with skipped) is 0. (Default: 'critical' returns).

=item B<--threshold-overload>

Set to overload default threshold values (syntax: section,[instance,]status,regexp)
It used before default thresholds (order stays).
Example: --threshold-overload='sysdrive,OK,formatting'

=item B<--warning>

Set warning threshold (syntax: type,regexp,threshold)
Example: --warning='temperature,.*,30'

=item B<--critical>

Set critical threshold (syntax: type,regexp,threshold)
Example: --critical='temperature,.*,40'

=back

=cut
