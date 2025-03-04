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

package apps::microsoft::mscs::local::mode::resourcestatus;

use base qw(centreon::plugins::templates::counter);

use strict;
use warnings;
use Win32::OLE;
use centreon::plugins::templates::catalog_functions qw(catalog_status_threshold_ng);

sub set_counters {
    my ($self, %options) = @_;
    
    $self->{maps_counters_type} = [
        { name => 'resource', type => 1, cb_prefix_output => 'prefix_resource_output', message_multiple => 'All resources are ok' }
    ];
    
    $self->{maps_counters}->{resource} = [
        {
            label => 'status',
            type => 2,
            unknown_default => '%{state} =~ /unknown/',
            critical_default => '%{state} =~ /failed|offline/',
            set => {
                key_values => [ { name => 'state' }, { name => 'display' }, { name => 'owner_node' } ],
                closure_custom_output => $self->can('custom_status_output'),
                closure_custom_perfdata => sub { return 0; },
                closure_custom_threshold_check => \&catalog_status_threshold_ng
            }
        }
    ];
}

sub custom_status_output {
    my ($self, %options) = @_;
    
    return 'state : ' . $self->{result_values}->{state} . ' [node: ' . $self->{result_values}->{owner_node}  . ']';
}

sub prefix_resource_output {
    my ($self, %options) = @_;
    
    return "Resource '" . $options{instance_value}->{display} . "' ";
}

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;
    
    $options{options}->add_options(arguments => {
        'filter-name:s' => { name => 'filter_name' }
    });

    return $self;
}

my %map_state = (
    -1 => 'unknown',
    0 => 'inherited',
    1 => 'initializing',
    2 => 'online',
    3 => 'offline',
    4 => 'failed',
    128 => 'pending',
    129 => 'online pending',
    130 => 'offline pending',
);

sub manage_selection {
    my ($self, %options) = @_;

    # winmgmts:{impersonationLevel=impersonate,authenticationLevel=pktPrivacy}!\\.\root\mscluster
    my $wmi = Win32::OLE->GetObject('winmgmts:root\mscluster');
    if (!defined($wmi)) {
        $self->{output}->add_option_msg(short_msg => "Cant create server object:" . Win32::OLE->LastError());
        $self->{output}->option_exit();
    }
    
    $self->{resource} = {};
    my $query = "Select * from MSCluster_Resource";
    my $resultset = $wmi->ExecQuery($query);
    foreach my $obj (in $resultset) {
        my $name = $obj->{Name};
        my $state = $map_state{$obj->{State}};
        my $id = defined($obj->{Id}) ? $obj->{Id} : $name;
        my $owner_node = defined($obj->{OwnerNode}) ? $obj->{OwnerNode} : '-';
    
        if (defined($self->{option_results}->{filter_name}) && $self->{option_results}->{filter_name} ne '' &&
            $name !~ /$self->{option_results}->{filter_name}/) {
            $self->{output}->output_add(long_msg => "skipping '" . $name . "': no matching filter.", debug => 1);
            next;
        }
    
        $self->{resource}->{$id} = { display => $name, state => $state, owner_node => $owner_node };
    }
}

1;

__END__

=head1 MODE

Check resource status.

=over 8

=item B<--filter-name>

Filter resource name (can be a regexp).

=item B<--unknown-status>

Set warning threshold for status (Default: '%{state} =~ /unknown/').
Can used special variables like: %{state}, %{display}

=item B<--warning-status>

Set warning threshold for status (Default: none).
Can used special variables like: %{state}, %{display}, %{owner_node}

=item B<--critical-status>

Set critical threshold for status (Default: '%{state} =~ /failed|offline/').
Can used special variables like: %{state}, %{display}, %{owner_node}

=back

=cut
