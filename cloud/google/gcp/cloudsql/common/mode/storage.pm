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

package cloud::google::gcp::cloudsql::common::mode::storage;

use base qw(cloud::google::gcp::custom::mode);

use strict;
use warnings;

sub get_metrics_mapping {
    my ($self, %options) = @_;

    my $metrics_mapping = {
        'database/disk/bytes_used' => {
            output_string => 'disk space usage: %.2f',
            perfdata => {
                absolute => {
                    nlabel => 'database.space.usage.bytes',
                    format => '%d',
                    unit => 'B',
                    change_bytes => 1
                }
            },
            threshold => 'space-usage',
            order => 1
        },
        'database/disk/read_ops_count' => {
            output_string => 'disk read IO operations: %.2f',
            perfdata => {
                absolute => {
                    nlabel => 'database.disk.read.io.operations.count',
                    format => '%.2f'
                },
                per_second => {
                    nlabel => 'database.disk.read.io.operations.persecond',
                    format => '%.2f'
                }
            },
            threshold => 'read-operations',
            order => 2
        },
        'database/disk/write_ops_count' => {
            output_string => 'disk write IO operations: %.2f',
            perfdata => {
                absolute => {
                    nlabel => 'database.disk.write.io.operations.count',
                    format => '%.2f'
                },
                per_second => {
                    nlabel => 'database.disk.write.io.operations.persecond',
                    format => '%.2f'
                }
            },
            threshold => 'write-operations',
            order => 3
        }
    };

    return $metrics_mapping;
}

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options, force_new_perfdata => 1);
    bless $self, $class;
    
    $options{options}->add_options(arguments => {
        'dimension-name:s'     => { name => 'dimension_name', default => 'resource.labels.database_id' },
        'dimension-operator:s' => { name => 'dimension_operator', default => 'equals' },
        'dimension-value:s'    => { name => 'dimension_value' },
        'filter-metric:s'      => { name => 'filter_metric' },
        "per-second"           => { name => 'per_second' },
        'timeframe:s'          => { name => 'timeframe' },
        'aggregation:s@'       => { name => 'aggregation' }
    });
    
    return $self;
}

sub check_options {
    my ($self, %options) = @_;
    $self->SUPER::check_options(%options);

    $self->{gcp_api} = 'cloudsql.googleapis.com';
    $self->{gcp_dimension_name} = (!defined($self->{option_results}->{dimension_name}) || $self->{option_results}->{dimension_name} eq '') ? 'resource.labels.database_id' : $self->{option_results}->{dimension_name};
    $self->{gcp_dimension_zeroed} = 'resource.labels.database_id';
    $self->{gcp_instance_key} = 'resource.labels.database_id';
    $self->{gcp_dimension_operator} = $self->{option_results}->{dimension_operator};
    $self->{gcp_dimension_value} = $self->{option_results}->{dimension_value};
}

1;

__END__

=head1 MODE

Check database storage metrics.

Example:

perl centreon_plugins.pl --plugin=cloud::google::gcp::cloudsql::mysql::plugin
--mode=diskio --dimension-value=mydatabaseid --filter-metric='space'
--aggregation='average' --verbose

Default aggregation: 'average' / All aggregations are valid.

=over 8

=item B<--dimension-name>

Set dimension name (Default: 'resource.labels.database_id'). Can be: 'resources.labels.region'.

=item B<--dimension-operator>

Set dimension operator (Default: 'equals'. Can also be: 'regexp', 'starts').

=item B<--dimension-value>

Set dimension value (Required).

=item B<--filter-metric>

Filter metrics (Can be: 'database/disk/bytes_used',
'database/disk/read_ops_count', 'databse/disk/write_ops_count') (Can be a regexp).

=item B<--timeframe>

Set timeframe in seconds (i.e. 3600 to check last hour).

=item B<--aggregation>

Set monitor aggregation (Can be multiple, Can be: 'minimum', 'maximum', 'average', 'total').

=item B<--warning-*> B<--critical-*>

Thresholds (Can be: 'space-usage', 'read-operations', 'write-operations').

=item B<--per-second>

Change the data to be unit/sec.

=back

=cut
