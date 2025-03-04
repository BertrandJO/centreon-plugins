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

package centreon::common::h3c::snmp::mode::components::psu;

use strict;
use warnings;

my %map_psu_status = (
    1 => 'notSupported',
    2 => 'normal',
    4 => 'entityAbsent',
    51 => 'psuError',
    91 => 'hardwareFaulty'
);

sub check {
    my ($self) = @_;

    $self->{output}->output_add(long_msg => "Checking power supplies");
    $self->{components}->{psu} = { name => 'power supplies', total => 0, skip => 0 };
    return if ($self->check_filter(section => 'psu'));

    my $mapping = {
        EntityExtErrorStatus => { oid => $self->{branch} . '.19', map => \%map_psu_status },
    };

    foreach my $instance (sort $self->get_instance_class(class => { 6 => 1 }) ) {
        my $result = $self->{snmp}->map_instance(mapping => $mapping, results => $self->{results}->{$self->{branch} . '.19'}, instance => $instance);

        next if (!defined($result->{EntityExtErrorStatus}));
        next if ($self->check_filter(section => 'psu', instance => $instance));
        if ($result->{EntityExtErrorStatus} =~ /entityAbsent/i) {
            $self->absent_problem(section => 'psu', instance => $instance);
            next;
        }

        my $name = '';
        $name = $self->get_short_name(instance => $instance) if (defined($self->{short_name}) && $self->{short_name} == 1);
        $name = $self->get_long_name(instance => $instance) unless (defined($self->{short_name}) && $self->{short_name} == 1 && defined($name) && $name ne '');
        $self->{components}->{psu}->{total}++;
        $self->{output}->output_add(
            long_msg => sprintf(
                "Power supply '%s' status is '%s' [instance: %s]",
                $name, $result->{EntityExtErrorStatus}, $instance
            )
        );
        my $exit = $self->get_severity(section => 'psu', value => $result->{EntityExtErrorStatus});
        if (!$self->{output}->is_status(value => $exit, compare => 'ok', litteral => 1)) {
            $self->{output}->output_add(
                severity => $exit,
                short_msg => sprintf("Power supply '%s' status is '%s'", $name, $result->{EntityExtErrorStatus})
            );
        }
    }
}

1;
