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

package storage::emc::vplex::restapi::mode::distributeddevices;

use base qw(centreon::plugins::templates::counter);

use strict;
use warnings;
use centreon::plugins::templates::catalog_functions qw(catalog_status_threshold_ng);

sub prefix_device_output {
    my ($self, %options) = @_;

    return sprintf(
        "distributed device '%s' ",
        $options{instance_value}->{device_name}
    );
}

sub set_counters {
    my ($self, %options) = @_;

    $self->{maps_counters_type} = [
        { name => 'devices', type => 1, cb_prefix_output => 'prefix_device_output', message_multiple => 'All distributed devices are ok' }
    ];

    $self->{maps_counters}->{devices} = [
        { label => 'health-status', type => 2, critical_default => '%{health_state} ne "ok"', set => {
                key_values => [ { name => 'health_state' }, { name => 'device_name' } ],
                output_template => 'health state: %s',
                closure_custom_perfdata => sub { return 0; },
                closure_custom_threshold_check => \&catalog_status_threshold_ng
            }
        },
        { label => 'operational-status', type => 2, critical_default => '%{operational_status} ne "ok"', set => {
                key_values => [ { name => 'operational_status' }, { name => 'device_name' } ],
                output_template => 'operational status: %s',
                closure_custom_perfdata => sub { return 0; },
                closure_custom_threshold_check => \&catalog_status_threshold_ng
            }
        },
        { label => 'service-status', type => 2, critical_default => '%{service_status} ne "running"', set => {
                key_values => [ { name => 'service_status' }, { name => 'device_name' } ],
                output_template => 'service status: %s',
                closure_custom_perfdata => sub { return 0; },
                closure_custom_threshold_check => \&catalog_status_threshold_ng
            }
        }
    ];
}

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options, force_new_perfdata => 1);
    bless $self, $class;

    $options{options}->add_options(arguments => {
        'filter-device-name:s' => { name => 'filter_device_name' }
    });

    return $self;
}

sub manage_selection {
    my ($self, %options) = @_;

    my $items = $options{custom}->get_distributed_devices();

    $self->{devices} = {};
    foreach my $item (@$items) {
        next if (defined($self->{option_results}->{filter_device_name}) && $self->{option_results}->{filter_device_name} ne '' &&
            $item->{name} !~ /$self->{option_results}->{filter_device_name}/);

        $self->{devices}->{ $item->{name} } = $item;
        $self->{devices}->{ $item->{name} }->{device_name} = $item->{name};
    }
}

1;

__END__

=head1 MODE

Check distributed devices.

=over 8

=item B<--filter-device-name>

Filter devices by device name (can be a regexp).

=item B<--warning-operational-status>

Set warning threshold for status.
Can used special variables like: %{operational_status}, %{device_name}

=item B<--critical-operational-status>

Set critical threshold for status (Default: '%{operational_status} ne "ok"').
Can used special variables like: %{operational_status}, %{device_name}

=item B<--warning-health-status>

Set warning threshold for status.
Can used special variables like: %{health_state}, %{device_name}

=item B<--critical-health-status>

Set critical threshold for status (Default: '%{health_state} ne "ok"').
Can used special variables like: %{health_state}, %{device_name}

=item B<--warning-service-status>

Set warning threshold for status.
Can used special variables like: %{service_status}, %{device_name}

=item B<--critical-service-status>

Set critical threshold for status (Default: '%{service_status} ne "running"').
Can used special variables like: %{service_status}, %{device_name}

=back

=cut
