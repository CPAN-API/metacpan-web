package MetaCPAN::Web::Model::API::Release;
use Moose;
use namespace::autoclean;

extends 'MetaCPAN::Web::Model::API';

=head1 NAME

MetaCPAN::Web::Model::Release - Catalyst Model

=head1 DESCRIPTION

Catalyst Model.

=head1 AUTHOR

Moritz Onken, Matthew Phillips

=head1 LICENSE

This library is free software. You can redistribute it and/or modify
it under the same terms as Perl itself.

=cut

sub get {
    my ( $self, $author, $release ) = @_;
    $self->request( '/release/by_name_and_author', undef,
        { name => $release, $author => uc($author) } );
}

sub distribution {
    my ( $self, $dist ) = @_;
    $self->request("/distribution/$dist");
}

sub latest_by_author {
    my ( $self, $author ) = @_;
    return $self->request(
        '/release/latest_by_author',
        undef,
        {
            author => $author,
            size   => 1000,
            fields => [qw< author distribution name status abstract date >],
            sort   => [qw< distribution version_numified:desc >]
        }
    );
}

sub all_by_author {
    my ( $self, $author, $size, $page ) = @_;
    $page = $page > 0 ? $page : 1;
    return $self->request( '/release/all_by_author', undef,
        { author => $author, size => $size, page => $page } );
}

sub recent {
    my ( $self, $page, $size, $type ) = @_;
    $self->request( '/release/recent', undef,
        { type => $type, page => $page, size => $size } );
}

sub modules {
    my ( $self, $author, $release ) = @_;
    $self->request( '/release/modules', undef,
        { author => $author, release => $release } );
}

sub find {
    my ( $self, $distribution ) = @_;
    $self->request( "/release/find/$distribution", );
}

# stolen from Module/requires
sub reverse_dependencies {
    my ( $self, $distribution, $page, $page_size, $sort ) = @_;
    $sort ||= { date => 'desc' };
    my $cv = $self->cv;

# TODO: do we need to do a taint-check on $distribution before inserting it into the url?
# maybe the fact that it came through as a Catalyst Arg is enough?
    $self->request(
        "/search/reverse_dependencies/$distribution",
        {
            query => {
                filtered => {
                    query  => { 'match_all' => {} },
                    filter => {
                        and => [
                            { term => { 'status'     => 'latest' } },
                            { term => { 'authorized' => 1 } },
                        ]
                    }
                }
            },
            size => $page_size,
            from => $page * $page_size - $page_size,
            sort => [$sort],
        }
        )->cb(
        sub {
            my $data = shift->recv;
            $cv->send(
                {
                    data =>
                        [ map { $_->{_source} } @{ $data->{hits}->{hits} } ],
                    total => $data->{hits}->{total},
                    took  => $data->{took}
                }
            );
        }
        );
    return $cv;
}

sub interesting_files {
    my ( $self, $author, $release ) = @_;
    $self->request(
        '/file/_search',
        {
            query => {
                filtered => {
                    query  => { match_all => {} },
                    filter => {
                        and => [
                            { term => { release   => $release } },
                            { term => { author    => $author } },
                            { term => { directory => \0 } },
                            { not  => { prefix    => { 'path' => 'xt/' } } },
                            { not  => { prefix    => { 'path' => 't/' } } },
                            {
                                or => [
                                    {
                                        and => [
                                            { term => { level => 0 } },
                                            {
                                                or => [
                                                    map {
                                                        {
                                                            term => {
                                                                'name' => $_
                                                            }
                                                        }
                                                        } qw(
                                                        AUTHORS
                                                        Build.PL
                                                        CHANGELOG
                                                        CHANGES
                                                        CONTRIBUTING
                                                        CONTRIBUTING.md
                                                        COPYRIGHT
                                                        CREDITS
                                                        ChangeLog
                                                        Changelog
                                                        Changes
                                                        Copying
                                                        FAQ
                                                        INSTALL
                                                        INSTALL.md
                                                        LICENCE
                                                        LICENSE
                                                        MANIFEST
                                                        META.json
                                                        META.yml
                                                        Makefile.PL
                                                        NEWS
                                                        README
                                                        README.markdown
                                                        README.md
                                                        README.mdown
                                                        README.mkdn
                                                        THANKS
                                                        TODO
                                                        ToDo
                                                        Todo
                                                        cpanfile
                                                        dist.ini
                                                        minil.toml
                                                        )
                                                ]
                                            }
                                        ]
                                    },
                                    map {
                                        { prefix     => { 'name' => $_ } },
                                            { prefix => { 'path' => $_ } },

                                 # With "prefix" we don't need the plural "s".
                                        } qw(
                                        ex eg
                                        example Example
                                        sample
                                        )
                                ]
                            }
                        ]
                    }
                }
            },

          # NOTE: We could inject author/release/distribution into each result
          # in the controller if asking ES for less data would be better.
            fields => [
                qw(
                    name documentation path pod_lines
                    author release distribution status
                    )
            ],
            size => 250,
        }
    );
}

sub versions {
    my ( $self, $dist ) = @_;
    $self->request(
        '/release/versions',
        undef,
        {
            distribution => $dist,
            size         => 250,
            sort         => 'date:desc',
            fields =>
                [qw( name date author version status maturity authorized )],
        }
    );
}

sub favorites {
    my ( $self, $dist ) = @_;
    $self->request( '/favorite/_search', {} );
}

sub topuploaders {
    my ( $self, $range ) = @_;
    $self->request( '/author/top_uploaders', undef, { range => $range } );
}

__PACKAGE__->meta->make_immutable;

1;
