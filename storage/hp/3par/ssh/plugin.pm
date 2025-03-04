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

package storage::hp::3par::ssh::plugin;

use strict;
use warnings;
use base qw(centreon::plugins::script_custom);

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;

    $self->{modes} = {
        'afc'          => 'storage::hp::3par::ssh::mode::afc',
        'cages'        => 'storage::hp::3par::ssh::mode::cages',
        'capacity'     => 'storage::hp::3par::ssh::mode::capacity',
        'components'   => 'storage::hp::3par::ssh::mode::hardware',
        'disk-usage'   => 'storage::hp::3par::ssh::mode::diskusage',
        'nodes'        => 'storage::hp::3par::ssh::mode::nodes',
        'psu'          => 'storage::hp::3par::ssh::mode::psu',
        'time'         => 'storage::hp::3par::ssh::mode::time',
        'uptime'       => 'storage::hp::3par::ssh::mode::uptime',
        'volume-usage' => 'storage::hp::3par::ssh::mode::volumeusage'
    };

    $self->{custom_modes}->{ssh} = 'storage::hp::3par::ssh::custom::custom';
    return $self;
}

1;

__END__

=head1 PLUGIN DESCRIPTION

Check HP 3par in SSH.

=cut
