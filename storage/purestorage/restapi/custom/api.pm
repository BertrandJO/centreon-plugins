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

package storage::purestorage::restapi::custom::api;

use strict;
use warnings;
use centreon::plugins::http;
use centreon::plugins::statefile;
use JSON::XS;
use Digest::MD5;

sub new {
    my ($class, %options) = @_;
    my $self  = {};
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
            'hostname:s' => { name => 'hostname' },
            'username:s' => { name => 'username' },
            'password:s' => { name => 'password' },
            'token:s'    => { name => 'token' },
            'timeout:s'  => { name => 'timeout' },
            'port:s'     => { name => 'port' },
            'proto:s'    => { name => 'proto' },
            'api-path:s' => { name => 'api_path' },
            'unknown-http-status:s'  => { name => 'unknown_http_status' },
            'warning-http-status:s'  => { name => 'warning_http_status' },
            'critical-http-status:s' => { name => 'critical_http_status' }
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

    $self->{hostname}     = (defined($self->{option_results}->{hostname})) ? $self->{option_results}->{hostname} : '';
    $self->{api_username} = (defined($self->{option_results}->{username})) ? $self->{option_results}->{username} : '';
    $self->{api_password} = (defined($self->{option_results}->{password})) ? $self->{option_results}->{password} : '';
    $self->{timeout}      = (defined($self->{option_results}->{timeout})) ? $self->{option_results}->{timeout} : 30;
    $self->{port}         = (defined($self->{option_results}->{port})) ? $self->{option_results}->{port} : 80;
    $self->{proto}        = (defined($self->{option_results}->{proto})) ? $self->{option_results}->{proto} : 'http';
    $self->{unknown_http_status} = (defined($self->{option_results}->{unknown_http_status})) ? $self->{option_results}->{unknown_http_status} : '%{http_code} < 200 or %{http_code} >= 300';
    $self->{warning_http_status} = (defined($self->{option_results}->{warning_http_status})) ? $self->{option_results}->{warning_http_status} : '';
    $self->{critical_http_status} = (defined($self->{option_results}->{critical_http_status})) ? $self->{option_results}->{critical_http_status} : '';
    $self->{token} = $self->{option_results}->{token};
 
    if ($self->{hostname} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify hostname option.");
        $self->{output}->option_exit();
    }

    $self->{cache}->check_options(option_results => $self->{option_results});

    if (defined($self->{token}) && $self->{token} ne '') {
        $self->{api_path} = (defined($self->{option_results}->{api_path})) ? $self->{option_results}->{api_path} : '/api/2.0';
        $self->{cache}->check_options(option_results => $self->{option_results});
        return 0;
    }

    $self->{api_path} = (defined($self->{option_results}->{api_path})) ? $self->{option_results}->{api_path} : '/api/1.11';
    if ($self->{api_username} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify username option.");
        $self->{output}->option_exit();
    }
    if ($self->{api_password} eq '') {
        $self->{output}->add_option_msg(short_msg => "Need to specify password option.");
        $self->{output}->option_exit();
    }

    return 0;
}

sub get_connection_infos {
    my ($self, %options) = @_;
    
    return $self->{hostname}  . '_' . $self->{http}->get_port();
}

sub build_options_for_httplib {
    my ($self, %options) = @_;

    $self->{option_results}->{hostname} = $self->{hostname};
    $self->{option_results}->{timeout} = $self->{timeout};
    $self->{option_results}->{port} = 443;
    $self->{option_results}->{proto} = 'https';
}

sub settings {
    my ($self, %options) = @_;

    return if (defined($self->{settings_done}));
    $self->{http}->add_header(key => 'Accept', value => 'application/json');
    $self->{http}->set_options(%{$self->{option_results}});
    $self->{settings_done} = 1;
}

sub clean_token {
    my ($self, %options) = @_;

    my $datas = { updated => time() };
    $self->{cache}->write(data => $datas);
}

sub request_auth_api {
    my ($self, %options) = @_;

    my $content = $self->{http}->request(
        method => $options{method},
        url_path => $options{url_path},
        header => $options{header},
        query_form_post => $options{query_form_post},
        unknown_status => $self->{unknown_http_status},
        warning_status => $self->{warning_http_status},
        critical_status => $self->{critical_http_status}
    );

    my $decoded;
    eval {
        $decoded = JSON::XS->new->utf8->decode($content);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot decode json response");
        $self->{output}->option_exit();
    }

    return $decoded;
}

sub get_api_token_v1 {
    my ($self, %options) = @_;
    
    my $json_request = { username => $self->{api_username}, password => $self->{api_password} };
    my $encoded;
    eval {
        $encoded = JSON::XS->new->utf8->encode($json_request);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot encode json request");
        $self->{output}->option_exit();
    }

    my $decoded = $self->request_auth_api(
        method => 'POST',
        header => ['Content-Type: application/json'],
        url_path => $self->{api_path} . '/auth/apitoken',
        query_form_post => $encoded
    );
    if (!defined($decoded->{api_token})) {
        $self->{output}->add_option_msg(short_msg => "Cannot get api token");
        $self->{output}->option_exit();
    }
    
    return $decoded->{api_token};
}

sub get_session_v1 {
    my ($self, %options) = @_;
    
    my $json_request = { api_token => $options{api_token} };
    my $encoded;
    eval {
        $encoded = JSON::XS->new->utf8->encode($json_request);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => "Cannot encode json request");
        $self->{output}->option_exit();
    }

    my $decoded = $self->request_auth_api(
        method => 'POST',
        header => ['Content-Type: application/json'],
        url_path => $self->{api_path} . '/auth/session',
        query_form_post => $encoded
    );
    my ($cookie) = $self->{http}->get_header(name => 'Set-Cookie');
    if (!defined($cookie)) {
        $self->{output}->add_option_msg(short_msg => "Cannot get session");
        $self->{output}->option_exit();
    }
    
    $cookie =~ /session=(.*);/;
    return $1;
}

sub credentials_v1 {
    my ($self, %options) = @_;

    my $has_cache_file = $self->{cache}->read(statefile => 'purestorage_api_' . Digest::MD5::md5_hex($self->{hostname} . '_' . $self->{api_username}));
    my $token = $self->{cache}->get(name => 'token');
    my $session = $self->{cache}->get(name => 'session');
    my $md5_secret_cache = $self->{cache}->get(name => 'md5_secret');
    my $md5_secret = Digest::MD5::md5_hex($self->{api_username} . $self->{api_password});

    if ($has_cache_file == 0 ||
        !defined($token) || !defined($session) ||
        (defined($md5_secret_cache) && $md5_secret_cache ne $md5_secret)
        ) {
        my $token = $self->get_api_token_v1();
        my $session = $self->get_session_v1(api_token => $token);

        my $datas = {
            updated => time(),
            token => $token,
            session => $session,
            md5_secret => $md5_secret
        };
        $self->{cache}->write(data => $datas);
    }

    return $session;
}

sub credentials_token_v2 {
    my ($self, %options) = @_;

    my $has_cache_file = $self->{cache}->read(statefile => 'purestorage_api_' . Digest::MD5::md5_hex($self->{hostname} . '_' . $self->{token}));
    my $token = $self->{cache}->get(name => 'token');
    my $md5_secret_cache = $self->{cache}->get(name => 'md5_secret');
    my $md5_secret = Digest::MD5::md5_hex($self->{token});

    if ($has_cache_file == 0 ||
        !defined($token) ||
        (defined($md5_secret_cache) && $md5_secret_cache ne $md5_secret)
        ) {
        my $content = $self->{http}->request(
            method => 'POST',
            query_form_post => '',
            url_path => '/api/login',
            header => [
                'api-token: ' . $self->{token},
                'Content-Type: application/json'
            ]
        );

        $token = $self->{http}->get_header(name => 'X-Auth-Token');

        if (!defined($token)) {
            $self->{output}->add_option_msg(short_msg => 'Cannot get token');
            $self->{output}->option_exit();
        }
        my $datas = {
            updated => time(),
            token => $token,
            md5_secret => $md5_secret
        };
        $self->{cache}->write(data => $datas);
    }

    return $token;
}

sub credentials {
    my ($self, %options) = @_;

    my $creds = {};
    if (defined($self->{token}) && $self->{token} ne '') {
        my $token = $self->credentials_token_v2();
        $creds = {
            header => ['X-Auth-Token: ' . $token],
            unknown_status => '',
            warning_status => '',
            critical_status => ''
        };
    } else {
        my $session = $self->credentials_v1();
        $creds = {
            header => ['Cookie: session=' . $self->{sesssion}],
            unknown_status => '',
            warning_status => '',
            critical_status => ''
        };
    }

    return $creds;
}

sub get_object {
    my ($self, %options) = @_;

    $self->settings();
    my $creds = $self->credentials();
    my $content = $self->{http}->request(
        method => 'GET',
        url_path => $self->{api_path} . $options{path},
        %$creds
    );

    # Maybe session is invalid. so we retry
    if ($self->{http}->get_code() < 200 || $self->{http}->get_code() >= 300) {
        $self->clean_token();
        $creds = $self->credentials();
        $content = $self->{http}->request(
            method => 'GET',
            url_path => $self->{api_path} . $options{path},
            %$creds,
            unknown_status => $self->{unknown_http_status},
            warning_status => $self->{warning_http_status},
            critical_status => $self->{critical_http_status}
        );
    }

    my $decoded;
    eval {
        $decoded = JSON::XS->new->utf8->decode($content);
    };
    if ($@) {
        $self->{output}->add_option_msg(short_msg => 'Cannot decode json response');
        $self->{output}->option_exit();
    }
    if ($decoded->{error} != 0) {
        $self->{output}->add_option_msg(short_msg => "api error $decoded->{error}: " . $decoded->{message});
        $self->{output}->option_exit();
    }

    return $decoded;
}


1;

__END__

=head1 NAME

Pure Storage REST API

=head1 SYNOPSIS

Pure Storage Rest API custom mode

=head1 REST API OPTIONS

=over 8

=item B<--hostname>

Pure Storage hostname.

=item B<--proto>

Set protocol (default: 'http')

=item B<--port>

Set HTTP port (default: 80)

=item B<--username>

Pure Storage username.

=item B<--password>

Pure Storage password.

=item B<--token>

Use token authentication (api v2 required).

=item B<--timeout>

Set HTTP timeout in seconds (Default: 30).

=item B<--api-path>

API base url path (Default: '/api/1.11').

=back

=head1 DESCRIPTION

B<custom>.

=cut
