package MetaCPAN::Web;    ## no critic (RequireFilenameMatchesPackage)

# ABSTRACT: Modern front-end for MetaCPAN

use strict;
use warnings;

# TODO: When we know everything will work reliably: $ENV{PLACK_ENV} ||= 'development';
#
use File::Basename;
my $root_dir;
my $dev_mode;

BEGIN {
    $root_dir = File::Basename::dirname(__FILE__);
    $dev_mode = $ENV{PLACK_ENV} && $ENV{PLACK_ENV} eq 'development';
}

BEGIN {
    if ($dev_mode) {
        $ENV{PLACK_SERVER}       = 'Standalone';
        $ENV{METACPAN_WEB_DEBUG} = 1;
    }
}

use Config::JFDI;
use lib "$root_dir/lib";
use File::Path    ();
use JSON::MaybeXS ();
use MIME::Base64  ();
use MetaCPAN::Web;
use Plack::Builder;
use Plack::App::File;
use Plack::App::URLMap;
use Plack::Middleware::Assets;
use Plack::Middleware::Headers;
use Plack::Middleware::Runtime;
use Plack::Middleware::MCLess;
use Plack::Middleware::ReverseProxy;
use Plack::Middleware::Session::Cookie::MetaCPAN;
use Plack::Middleware::ServerStatus::Lite;
use Try::Tiny;
use CHI;

my $tempdir = "$root_dir/var/tmp";

# explicitly call ->to_app on every Plack::App::* for performance
my $app = Plack::App::URLMap->new;

# Static content
{
    my $static_app = Plack::App::File->new( root => 'root/static' )->to_app;
    $app->map( '/static/' => $static_app );
}

# favicon
{
    my $fav_app
        = Plack::App::File->new( file => 'root/static/icons/favicon.ico' )
        ->to_app;
    $app->map( '/favicon.ico' => $fav_app );
}

# Main catalyst app
{
    my $core_app = MetaCPAN::Web->psgi_app;

    my $config = Config::JFDI->new(
        name => 'MetaCPAN::Web',
        path => $root_dir,
    );

    die 'cookie_secret not configured' unless $config->get->{cookie_secret};

    # Add session cookie here only
    $core_app = Plack::Middleware::Session::Cookie::MetaCPAN->wrap(
        $core_app,
        session_key => 'metacpan_secure',
        expires     => 2**30,
        secure      => ( ( $ENV{PLACK_ENV} || q[] ) ne 'development' ),
        httponly    => 1,
        secret      => $config->get->{cookie_secret},
    );

    $app->map( q[/] => $core_app );
}

$app = $app->to_app;

unless ( $ENV{HARNESS_ACTIVE} ) {
    my $scoreboard = "$root_dir/var/tmp/scoreboard";
    maybe_make_path($scoreboard);

    $app = Plack::Middleware::ServerStatus::Lite->wrap(
        $app,
        path       => '/server-status',
        allow      => ['127.0.0.1'],
        scoreboard => $scoreboard,
    ) unless $0 =~ /\.t$/;
}

$app = Plack::Middleware::Runtime->wrap($app);
my @js_files = map {"/static/js/$_.js"} (
    qw(
        jquery.min
        jquery.tablesorter
        jquery.relatize_date
        jquery.qtip.min
        jquery.autocomplete.min
        mousetrap.min
        shCore
        shBrushPerl
        shBrushPlain
        shBrushYaml
        shBrushJScript
        shBrushDiff
        shBrushCpp
        shBrushCPANChanges
        cpan
        toolbar
        github
        contributors
        dropdown
        bootstrap/bootstrap-dropdown
        bootstrap/bootstrap-collapse
        bootstrap/bootstrap-modal
        bootstrap/bootstrap-tooltip
        bootstrap/bootstrap-affix
        bootstrap-slidepanel
        syntaxhighlighter
        ),
);
my @css_files
    = map { my $f = $_; $f =~ s{^root/}{/}; $f } glob 'root/static/css/*.css';

if ($dev_mode) {
    my $wrap = $app;
    $app = sub {
        my $env = shift;
        push @{ $env->{'psgix.assets'} ||= [] }, @js_files, @css_files;
        $wrap->($env);
    };
}
else {
    # Only need for live
    my $cache = CHI->new(
        driver   => 'File',
        root_dir => "$root_dir/var/tmp/less.cache",
    );

    # Wrap up to serve lessc parsed files
    $app = Plack::Middleware::MCLess->wrap(
        $app,
        cache     => $cache,
        cache_ttl => '60 minutes',
        root      => 'root/static',
        files     => [
            map {"root/static/less/$_.less"}
                qw(
                style
                )
        ],
    );

    for my $assets ( \@js_files, \@css_files ) {
        $app = Plack::Middleware::Assets->wrap( $app,
            files => [ map {"root$_"} @$assets ] );
    }
}

# Handle surrogate (fastly caching)
{
    my $hour_ttl = 60 * 60;
    my $day_ttl  = $hour_ttl * 24;

    $app = builder {

        # Tell fastly to cache _asset and _asset_less for a day
        enable_if { $_[0]->{PATH_INFO} =~ m{^/_asset} } 'Headers',
            set => [ 'Surrogate-Control' => "max-age=${day_ttl}" ];

        # Tell fastly to cache /static/ for an hour
        enable_if { $_[0]->{PATH_INFO} =~ m{^/static} } 'Headers',
            set => [ 'Surrogate-Control' => "max-age=${hour_ttl}" ];

        $app;
    };
}

sub maybe_make_path {
    my $path = shift;

    return if -d $path;

    File::Path::make_path($path) or die "Can't make_path $path: $!";
}

$app = Plack::Middleware::ReverseProxy->wrap($app);

return $app;
