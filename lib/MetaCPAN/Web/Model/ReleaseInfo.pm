package MetaCPAN::Web::Model::ReleaseInfo;

use strict;
use warnings;
use MetaCPAN::Moose;

extends 'Catalyst::Model';

use List::AllUtils qw( all );
use MetaCPAN::Web::Types qw( HashRef Object );
use URI;
use URI::Escape qw(uri_escape uri_unescape);
use URI::QueryParam;    # Add methods to URI.
use Importer 'MetaCPAN::Web::Elasticsearch::Adapter' =>
    qw/ single_valued_arrayref_to_scalar /;

sub ACCEPT_CONTEXT {
    my ( $class, $c, $args ) = @_;
    return $class->new(
        {
            c => $c,
            %$args,
        }
    );
}

# Setting these attributes to required will cause the app to exit when it tries
# to instantiate the model on startup.

has author => (
    is       => 'ro',
    isa      => HashRef,
    required => 0,
);

has c => (
    is            => 'ro',
    isa           => Object,
    required      => 0,
    documentation => 'Catlyst context object',
);

has distribution => (
    is       => 'ro',
    isa      => HashRef,
    required => 0,
);

has release => (
    is       => 'ro',
    isa      => HashRef,
    required => 0,
);

sub summary_hash {
    my ($self) = @_;
    return {
        author => $self->author,
        irc    => $self->groom_irc,
        issues => $self->normalize_issues,
    };
}

sub groom_irc {
    my ($self) = @_;

    my $irc = $self->release->{metadata}{resources}{x_IRC};
    my $irc_info = ref $irc ? {%$irc} : { url => $irc };

    if ( !$irc_info->{web} && $irc_info->{url} ) {
        my $url    = URI->new( $irc_info->{url} );
        my $scheme = $url->scheme;
        if ( $scheme && ( $scheme eq 'irc' || $scheme eq 'ircs' ) ) {
            my $ssl  = $scheme eq 'ircs';
            my $host = $url->authority;
            my $port;
            my $user;
            if ( $host =~ s/:(\d+)$// ) {
                $port = $1;
            }
            if ( $host =~ s/^(.*)@// ) {
                $user = $1;
            }
            my $path = uri_unescape( $url->path );
            $path =~ s{^/}{};
            my $channel
                = $path || $url->fragment || $url->query_param('channel');
            $channel =~ s/^(?![#~!+])/#/;
            $channel = uri_escape($channel);

            if ( $host =~ /(?:^|\.)freenode\.net$/ ) {
                $irc_info->{web}
                    = "https://webchat.freenode.net/?randomnick=1&prompt=1&channels=${channel}";
            }
            else {
                my $server = $host
                    . (
                      $ssl ? q{:+} . ( $port || 6697 )
                    : $port ? ":$port"
                    :         q{}
                    );
                $irc_info->{web}
                    = "https://chat.mibbit.com/?channel=${channel}&server=${server}";
            }
        }
    }

    return $irc_info;
}

# Normalize issue info into a simple hashref.
# The view was getting messy trying to ensure that the issue count only showed
# when the url in the 'release' matched the url in the 'distribution'.
# If a release links to github, don't show the RT issue count.
# However, there are many ways for a release to specify RT :-/
# See t/model/issues.t for examples.

sub rt_url_prefix {
    'https://rt.cpan.org/Public/Dist/Display.html?Name=';
}

sub normalize_issues {
    my ($self) = @_;
    my ( $release, $distribution ) = ( $self->release, $self->distribution );

    my $issues = {};

    my $bugtracker = ( $release->{resources} || {} )->{bugtracker} || {};

    if ( $bugtracker->{web} && $bugtracker->{web} =~ /^https?:/ ) {
        $issues->{url} = $bugtracker->{web};
    }
    elsif ( $bugtracker->{mailto} ) {
        $issues->{url} = 'mailto:' . $bugtracker->{mailto};
    }
    else {
        $issues->{url}
            = $self->rt_url_prefix . uri_escape( $release->{distribution} );
    }

    for my $bugs ( values %{ $distribution->{bugs} || {} } ) {

       # Include the active issue count, but only if counts came from the same
       # source as the url specified in the resources.
        if (
           # If the specified url matches the source we got our counts from...
            $self->normalize_issue_url( $issues->{url} ) eq
            $self->normalize_issue_url( $bugs->{source} )

            # or if both of them look like rt.
            or all {m{^https?://rt\.cpan\.org(/|$)}}
            ( $issues->{url}, $bugs->{source} )
            )
        {
            $issues->{active} = $bugs->{active};
        }
    }

    return $issues;
}

sub normalize_issue_url {
    my ( $self, $url ) = @_;
    $url
        =~ s{^https?:// (?:www\.)? ( github\.com / ([^/]+) / ([^/]+) ) (.*)$}{https://$1}x;
    $url =~ s{
        ^https?:// rt\.cpan\.org /
        (?:
            NoAuth/Bugs\.html\?Dist=
        |
            (?:Public/)?Dist/Display\.html\?Name=
        )
    }{https://rt.cpan.org/Public/Dist/Display.html?Name=}x;

    return $url;
}

__PACKAGE__->meta->make_immutable;

1;
