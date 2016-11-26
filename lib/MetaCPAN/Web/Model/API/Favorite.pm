package MetaCPAN::Web::Model::API::Favorite;
use Moose;
use namespace::autoclean;

extends 'MetaCPAN::Web::Model::API';

use List::MoreUtils qw(uniq);
use Ref::Util qw(is_arrayref);
use Importer 'MetaCPAN::Web::Elasticsearch::Adapter' =>
    qw/ single_valued_arrayref_to_scalar /;

sub get {
    my ( $self, $user, @distributions ) = @_;
    @distributions = uniq @distributions;
    my $cv = $self->cv;

    # If there are no distributions this will build a query with an empty
    # filter and ES will return a parser error... so just skip it.
    if ( !@distributions ) {
        $cv->send( {} );
        return $cv;
    }

    $cv->send(
        $self->request(
            '/favorite/agg_dists_user', undef,
            { distributions => \@distributions, user => $user }
        )
    );

    return $cv;
}

sub by_user {
    my ( $self, $users, $size ) = @_;
    my @users = is_arrayref $users ? @{$users} : $users;
    return $self->request(
        '/favorite/by_user',
        undef,
        {
            fields => [qw<date author distribution>],
            sort   => 'distribution',
            size   => $size || 250,
            user   => \@users,
        }
    );
}

sub recent {
    my ( $self, $page, $size ) = @_;
    $self->request( '/favorite/recent', undef,
        { size => $size, page => $page } );
}

sub leaderboard {
    my ($self) = @_;
    $self->request('/favorite/leaderboard');
}

sub find_plussers {
    my ( $self, $distribution ) = @_;

    # search for all users, match all according to the distribution.
    my $plusser      = $self->by_distribution($distribution);
    my $plusser_data = $plusser->recv;

    # store in an array.
    my @plusser_users = map { $_->{user} }
        map { single_valued_arrayref_to_scalar( $_->{_source} ) }
        @{ $plusser_data->{hits}->{hits} };
    my $total_plussers = @plusser_users;

    # find plussers by pause ids.
    my $authors
        = @plusser_users
        ? $self->plusser_by_id( \@plusser_users )->recv->{hits}->{hits}
        : [];

    my @plusser_details = map {
        {
            id  => $_->{_source}->{pauseid},
            pic => $_->{_source}->{gravatar_url},
        }
    } @{$authors};

    my $total_authors = @plusser_details;

    # find total non pauseid users who have ++ed the dist.
    my $total_nonauthors = ( $total_plussers - $total_authors );

    # number of pauseid users can be more than total plussers
    # then set 0 to non pauseid users
    $total_nonauthors = 0 if $total_nonauthors < 0;

    return (
        {
            plusser_authors => \@plusser_details,
            plusser_others  => $total_nonauthors,
            plusser_data    => $distribution
        }
    );

}

sub by_distribution {
    my ( $self, $distribution ) = @_;

    return $self->request( '/favorite/by_distribution', undef,
        { size => 1000, fields => "user" } );
}

# finding the authors who have ++ed the distribution.
sub plusser_by_id {
    my ( $self, $users ) = @_;
    return $self->request(
        '/favorite/plusser_by_user',
        undef,
        {
            fields => [qw< pauseid gravatar_url >],
            size   => 1000,
            sort   => 'pauseid'
        }
    );
}

__PACKAGE__->meta->make_immutable;

1;
