package MetaCPAN::Web::Controller::Search;

use strict;
use warnings;

use Moose;

BEGIN { extends 'MetaCPAN::Web::Controller' }

use Plack::Response;

sub index : Path : Args(0) {
    my ( $self, $c ) = @_;
    my $req = $c->req;

    my $page_size = $req->get_page_size(20);

    # Redirect back to main page if search query is empty irrespective of
    # whether we're feeling lucky or not.
    unless ( $req->param('q') ) {
        $c->res->redirect(q{/});
        $c->detach;
    }

    my $query = join( q{ }, $req->param('q') );

    # translate Foo/Bar.pm to Foo::Bar
    if ( $query =~ m{.pm\b} ) {
        $query =~ s{/}{::}g;
        $query =~ s{\.pm\b}{};
    }

    my $model = $c->model('API::Module');
    my $from  = ( $req->page - 1 ) * $page_size;
    if (
        $req->parameters->{lucky}
        or

        # DuckDuckGo-like syntax for bangs that redirect to the first
        # result.
        $query =~ s[^ (?: \\ | ! ) ][]x
        )
    {
        my $module = $model->first($query)->recv;
        if ( $query eq $module ) {
            $c->res->redirect("/pod/$module");
            $c->detach;
        }
        else {
            my $author = $c->model('API::Author')->search($query)->recv;
            if (   $author->{total} == 1
                && $query eq $author->{results}->[0]->{pauseid} )
            {
                $c->res->redirect( '/author/' . uc($query) );
                $c->detach;
            }
            elsif ($module) {
                $c->res->redirect("/pod/$module");
                $c->detach;
            }
            else {
                $c->detach('/not_found') unless ($module);
            }
        }
    }
    else {
        my $user = $c->user_exists ? $c->user->id : undef;

        # these would be nicer if we had variable-length lookbehinds...
        $query =~ s{(^|\s)author:([a-zA-Z]+)(?=\s|$)}{$1author:\U$2\E}g;
        $query
            =~ s/(^|\s)dist(ribution)?:([\w-]+)(?=\s|$)/$1distribution:$3/g;
        $query
            =~ s/(^|\s)module:(\w[\w:]*)(?=\s|$)/$1module.name.analyzed:$2/g;

        my $results
            = $query =~ /(distribution|module\.name\S*):/
            ? $model->search_expanded( $query, $from, $page_size, $user )
            : $model->search_collapsed( $query, $from, $page_size, $user );

        my @dists = $query =~ /distribution:(\S+)/g;

        my $authors = $c->model('API::Author')->search( $query, $from );
        ( $results, $authors ) = ( $results->recv, $authors->recv );

        if ( !$results->{total} && !$authors->{total} ) {
            my $suggest = $query;
            $suggest =~ s/\s*:+\s*/::/g;
            if ( $suggest ne $query ) {
                $c->stash(
                    {
                        suggest => $suggest,
                    }
                );
            }
            $c->stash( template => 'no_result.html' );
            $c->detach;
        }

        $c->stash(
            {
                %$results,
                single_dist => @dists == 1,
                authors     => $authors,
                template    => 'search.html',
                page_size   => $page_size,
            }
        );
    }
}

__PACKAGE__->meta->make_immutable;

1;
