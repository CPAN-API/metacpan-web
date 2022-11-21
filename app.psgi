package MetaCPAN::Web::App;    ## no critic (RequireFilenameMatchesPackage)

# ABSTRACT: Modern front-end for MetaCPAN

use strict;
use warnings;

# TODO: When we know everything will work reliably: $ENV{PLACK_ENV} ||= 'development';
#
use File::Basename     ();
use Config::ZOMG       ();
use Log::Log4perl      ();
use Log::Log4perl::MDC ();
use File::Spec         ();
use File::Path         ();
use Plack::Builder     qw( builder enable );
use Digest::SHA        ();

my $root_dir;
my $dev_mode;
my $config;

BEGIN {
    $root_dir = File::Basename::dirname(__FILE__);
    $dev_mode = $ENV{PLACK_ENV} && $ENV{PLACK_ENV} eq 'development';
    $config   = Config::ZOMG->open(
        name => 'MetaCPAN::Web',
        path => $root_dir,
    );

    if ($dev_mode) {
        $ENV{PLACK_SERVER}       = 'Standalone';
        $ENV{METACPAN_WEB_DEBUG} = 1;
    }

    my $log4perl_config
        = File::Spec->rel2abs( $config->{log4perl_file} || 'log4perl.conf',
        $root_dir );
    Log::Log4perl::init($log4perl_config);

# use a unique package and tell l4p to ignore it when finding the warning location.
    package MetaCPAN::Web::LogDispatcher;
    Log::Log4perl->wrapper_register(__PACKAGE__);

    $SIG{__WARN__} = sub {
        my $logger = eval { Log::Log4perl->get_logger };
        if ($logger) {
            $logger->warn(@_);
        }
        else {
            warn @_;
        }
    };
}

use lib "$root_dir/lib";
use MetaCPAN::Web;

# do not use the read only mount point when running from a docker container
my $tempdir = is_linux_container() ? '/var/tmp' : "$root_dir/var/tmp";

STDERR->autoflush;

# explicitly call ->to_app on every Plack::App::* for performance
builder {

    enable sub {
        my $app = shift;
        sub {
            my ($env) = @_;
            if ( $env->{HTTP_FASTLY_SSL} ) {
                $env->{HTTPS}             = 'ON';
                $env->{'psgi.url_scheme'} = 'https';
            }
            if ( my $host = $env->{HTTP_X_FORWARDED_HOST} ) {
                $env->{HTTP_HOST} = $host;
            }
            if ( my $port = $env->{HTTP_X_FORWARDED_PORT} ) {
                $env->{SERVER_PORT} = $port;
            }
            if ( my $addrs = $env->{HTTP_X_FORWARDED_FOR} ) {
                my @addrs = map s/^\s+//r =~ s/\s+$//r, split /,/, $addrs;
                $env->{REMOTE_ADDR} = $addrs[0];
            }
            $app->($env);
        };
    };
    enable sub {

        # put all security-related headers here
        my $app = shift;
        sub {
            my ($env) = @_;
            Plack::Util::response_cb(
                $app->($env),
                sub {
                    push @{ $_[0][1] }, 'Content-Security-Policy' => join(
                        '; ',
                        "default-src * data: 'unsafe-inline'",
                        "frame-ancestors 'self' *.metacpan.org",

        # temporary 'unsafe-eval' because root/static/js/jquery.tablesorter.js
                        "script-src 'self' 'unsafe-eval' 'unsafe-inline' *.metacpan.org *.google-analytics.com *.google.com www.gstatic.com",

                        ),
                        'X-Frame-Options'        => 'SAMEORIGIN',
                        'X-XSS-Protection'       => '1; mode=block',
                        'X-Content-Type-Options' => 'nosniff',
                        ;
                },
            );
        };
    };
    enable sub {
        my $app = shift;
        sub {
            my ($env) = @_;
            my $request_id = Digest::SHA::sha1_hex( join( "\0",
                $env->{REMOTE_ADDR}, $env->{REQUEST_URI}, time, $$, rand, ) );
            $env->{'MetaCPAN::Web.request_id'} = $request_id;

            my $mdc = Log::Log4perl::MDC->get_context;
            %$mdc = (
                request_id => $request_id,
                ip         => $env->{REMOTE_ADDR},
                method     => $env->{REMOTE_METHOD},
                url        => $env->{REQUEST_URI},
                map +(
                    lc($_) =~ s/^http_(.)/\u$1/r
                        =~ s/_(.)/-\u$1/gr => $env->{$_}
                ),
                grep /^HTTP_(?:SEC_|REFERER$)/,
                keys %$env
            );

            $app->($env);
        };
    };
    enable 'Runtime';

    enable 'FixMissingBodyInRedirect';

    enable '+MetaCPAN::Middleware::OldUrls';

    enable '+MetaCPAN::Middleware::Static' => (
        root     => $root_dir,
        dev_mode => $dev_mode,
        temp_dir => $tempdir,
        config   => $config,
    );

    builder {
        die 'cookie_secret not configured'
            unless $config->{cookie_secret};

        # Add session cookie here only
        enable '+MetaCPAN::Middleware::Session::Cookie' => (
            session_key => 'metacpan_secure',
            expires     => 2**30,
            secure      => ( !$dev_mode ),
            httponly    => 1,
            secret      => $config->{cookie_secret},
        );

        MetaCPAN::Web->psgi_app;
    };
};

sub is_linux_container {
    return -e '/proc/1/cgroup';
}
