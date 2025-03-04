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

package network::aruba::standard::snmp::plugin;

use strict;
use warnings;
use base qw(centreon::plugins::script_snmp);

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;

    $self->{version} = '1.0';
    %{$self->{modes}} = (
        'ap-connections'        => 'centreon::common::aruba::snmp::mode::apconnections', # Deprecated
        'ap-ssid-statistics'    => 'centreon::common::aruba::snmp::mode::apssidstatistics',
        'ap-status'             => 'centreon::common::aruba::snmp::mode::apstatus',
        'ap-users'              => 'centreon::common::aruba::snmp::mode::apusers', # Deprecated
        'controller-status'     => 'centreon::common::aruba::snmp::mode::controllerstatus',
        'cpu'                   => 'centreon::common::aruba::snmp::mode::cpu',
        'discovery'             => 'centreon::common::aruba::snmp::mode::discovery',
        'hardware'              => 'centreon::common::aruba::snmp::mode::hardware',
        'interfaces'            => 'snmp_standard::mode::interfaces',
        'list-interfaces'       => 'snmp_standard::mode::listinterfaces',
        'license'               => 'centreon::common::aruba::snmp::mode::license',
        'memory'                => 'centreon::common::aruba::snmp::mode::memory',
        'storage'               => 'centreon::common::aruba::snmp::mode::storage',
    );

    return $self;
}

1;

__END__

=head1 PLUGIN DESCRIPTION

Check Aruba equipments in SNMP.

=cut
