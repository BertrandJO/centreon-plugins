#
# Copyright 2022 Centreon (http://www.centreon.com/)
#
# Centreon is a full-fpemged industry-strength solution that meets
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

package network::viptela::snmp::mode::components::pem;

use strict;
use warnings;

sub load {}

sub check {
    my ($self) = @_;

    $self->{output}->output_add(long_msg => "Checking pem");
    $self->{components}->{pem} = { name => 'pem', total => 0, skip => 0 };
    return if ($self->check_filter(section => 'pem'));

    my ($exit, $warn, $crit, $checked);
    foreach (@{$self->{results}}) {
        next if ($_->{type} ne 'pem');
        my $instance = 'pem.' . $_->{name};
        next if ($self->check_filter(section => 'pem', instance => $instance));
        $self->{components}->{pem}->{total}++;

        $self->{output}->output_add(
            long_msg => sprintf(
                "pem '%s' status is '%s' [instance: %s]",
                $_->{name},
                $_->{status},
                $instance
            )
        );
        $exit = $self->get_severity(label => 'default', section => 'pem', value => $_->{status});
        if (!$self->{output}->is_status(value => $exit, compare => 'ok', litteral => 1)) {
            $self->{output}->output_add(
                severity => $exit,
                short_msg => sprintf("pem '%s' status is '%s'", $_->{name}, $_->{status})
            );
        }
    }
}

1;
