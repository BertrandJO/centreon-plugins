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

package apps::vmware::vcsa::restapi::custom::api;

use base qw(centreon::plugins::mode);

use strict;
use warnings;
use centreon::plugins::http;
use centreon::plugins::statefile;
use JSON::XS;
use Digest::MD5 qw(md5_hex);

sub new {
    my ($class, %options) = @_;
    my $self = $class->SUPER::new(package => __PACKAGE__, %options);
    bless $self, $class;

    if (!defined($options{output})) {
        print "Class Custom: Need to specify 'output' argument.\n";
        exit 3;
    }
    if (!defined($options{options})) {
        $options{output}->add_option_msg(short_msg => "Class Custom: Need to specify 'options' argument.");
        $options{output}->option_exit();
    }
    
    if (!defined($options{noptions})) {
        $options{options}->add_options(arguments => {
            'hostname:s'        => { name => 'hostname' },
            'port:s'            => { name => 'port'},
            'proto:s'           => { name => 'proto' },
            'api-username:s'    => { name => 'api_username' },
            'api-password:s'    => { name => 'api_password' },
            'timeout:s'         => { name => 'timeout', default => 30 }
        });
    }
    
    $options{options}->add_help(package => __PACKAGE__, sections => 'REST API OPTIONS', once => 1);

    $self->{output} = $options{output};
    $self->{http} = centreon::plugins::http->new(%options);
    $self->{cache} = centreon::plugins::statefile->new(%options);

    return $self;
}

sub set_options {
    my ($self, %options) = @_;

    $self->{option_results} = $options{option_results};
}

sub set_defaults {}

sub check_options {
    my ($self, %options) = @_;

    $self->{hostname} = (defined($self->{option_results}->{hostname})) ? $self->{option_results}->{hostname} : undef;
    $self->{port} = (defined($self->{option_results}->{port})) ? $self->{option_results}->{port} : 443;
    $self->{proto} = (defined($self->{option_results}->{proto})) ? $self->{option_results}->{proto} : 'https';
    $self->{timeout} = (defined($self->{option_results}->{timeout})) ? $self->{option_results}->{timeout} : 30;
    $self->{api_username} = (defined($self->{option_results}->{api_username})) ? $self->{option_results}->{api_username} : undef;
    $self->{api_password} = (defined($self->{option_results}->{api_password})) ? $self->{option_results}->{api_password} : undef;

    if (!defined($self->{hostname}) || $self->{hostname} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify --hostname option.");
        $self->{output}->option_exit();
    }
    if (!defined($self->{api_username}) || $self->{api_username} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify --api-username option.");
        $self->{output}->option_exit();
    }
    if (!defined($self->{api_password}) || $self->{api_password} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify --api-password option.");
        $self->{output}->option_exit();
    }

    $self->{cache}->check_options(option_results => $self->{option_results});

    return 0;
}

sub build_options_for_httplib {
    my ($self, %options) = @_;

    $self->{option_results}->{hostname} = $self->{hostname};
    $self->{option_results}->{port} = $self->{port};
    $self->{option_results}->{proto} = $self->{proto};
    $self->{option_results}->{timeout} = $self->{timeout};
}

sub settings {
    my ($self, %options) = @_;

    $self->build_options_for_httplib();
    $self->{http}->add_header(key => 'Content-Type', value => 'application/json;charset=UTF-8');
    $self->{http}->add_header(key => 'Accept', value => 'application/json;charset=UTF-8');
    $self->{http}->set_options(%{$self->{option_results}});
}

sub json_decode {
    my ($self, %options) = @_;

    my $decoded;
    eval {
        $decoded = JSON::XS->new->utf8->allow_nonref(1)->decode($options{content});
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot decode json response: $@");
        $self->{output}->option_exit();
    }

    return $decoded;
}

sub clean_session {
    my ($self, %options) = @_;

    my $datas = { last_timestamp => time() };
    $self->{cache}->write(data => $datas);
}

sub authv2 {
    my ($self, %options) = @_;

    my $content = $self->{http}->request(
        method => 'POST',
        query_form_post => '',
        url_path => '/api/session',
        credentials => 1,
        basic => 1,
        username => $self->{api_username},
        password => $self->{api_password},
        warning_status => '',
        unknown_status => '',
        critical_status => ''
    );
    my $http_code = $self->{http}->get_code();
    return ($http_code, $self->{http}->get_message()) if ($http_code < 200 || $http_code >= 300);

    my $decoded = $self->json_decode(content => $content);

    if (defined($decoded) && ref($decoded) eq '' && $decoded ne '') {
        return (200, 'ok', $decoded);
    }

    return (500, 'Error retrieving session_id');
}

sub authv1 {
    my ($self, %options) = @_;

    my $content = $self->{http}->request(
        method => 'POST',
        query_form_post => '',
        url_path => '/rest/com/vmware/cis/session',
        credentials => 1,
        basic => 1,
        username => $self->{api_username},
        password => $self->{api_password},
        warning_status => '',
        unknown_status => '',
        critical_status => ''
    );
    my $http_code = $self->{http}->get_code();
    return ($http_code, $self->{http}->get_message()) if ($http_code < 200 || $http_code >= 300);

    my $decoded = $self->json_decode(content => $content);

    if (defined($decoded) && defined($decoded->{value})) {
        return (200, 'ok', $decoded->{value});
    }

    return (500, 'Error retrieving session_id');
}

sub authenticate {
    my ($self, %options) = @_;

    my ($http_code, $http_message);
    my $has_cache_file = $self->{cache}->read(statefile => 'vcsa_api_' . md5_hex($self->{option_results}->{hostname} . '_' . $self->{option_results}->{api_username}));
    my $session_id = $self->{cache}->get(name => 'session_id');
    my $md5_secret_cache = $self->{cache}->get(name => 'md5_secret');
    my $md5_secret = md5_hex($self->{api_username} . $self->{api_password});

    if ($has_cache_file != 0 &&
        defined($session_id) &&
        (defined($md5_secret_cache) && $md5_secret_cache eq $md5_secret)) {
        return $session_id;
    }

    ($http_code, $http_message, $session_id) = $self->authv2();
    if ($http_code != 200) {
        ($http_code, $http_message, $session_id) = $self->authv1();
    }

    if (!defined($session_id)) {
        $self->{output}->add_option_msg(short_msg => "authenticate error [code: '" . $http_code . "'] [message: '" . $http_message . "']");
        $self->{output}->option_exit();
    }

    my $datas = { last_timestamp => time(), session_id => $session_id, md5_secret => $md5_secret };
    $self->{cache}->write(data => $datas);

    return $session_id;
}

sub request_api {
    my ($self, %options) = @_;

    $self->settings();
    my $session_id = $self->authenticate();
    
    my $content = $self->{http}->request(
        %options,
        header => [
            'vmware-api-session-id: ' . $session_id
        ],
        warning_status => '',
        unknown_status => '',
        critical_status => ''
    );

    # Maybe there is an issue with the session_id. So we retry.
    if ($self->{http}->get_code() != 200) {
        $self->clean_session();
        $session_id = $self->authenticate();
        $content = $self->{http}->request(
            %options,
            header => [
                'vmware-api-session-id: ' . $session_id
            ],
            warning_status => '',
            unknown_status => '',
            critical_status => ''
        );
    }

    my $decoded = $self->json_decode(content => $content);
    if (!defined($decoded)) {
        $self->{output}->add_option_msg(short_msg => "Error while retrieving data (add --debug option for detailed message)");
        $self->{output}->option_exit();
    }
    if ($self->{http}->get_code() != 200) {
        $self->{output}->add_option_msg(short_msg => 'api request error: ' . (defined($decoded->{type}) ? $decoded->{type} : 'unknown'));
        $self->{output}->option_exit();
    }

    return $decoded;
}

1;

__END__

=head1 NAME

VCSA Rest API

=head1 REST API OPTIONS

=over 8

=item B<--hostname>

Set hostname or IP of vsca.

=item B<--port>

Set port (Default: '443').

=item B<--proto>

Specify https if needed (Default: 'https').

=item B<--api-username>

Set username.

=item B<--api-password>

Set password.

=item B<--timeout>

Threshold for HTTP timeout (Default: '30').

=back

=cut
