use strict;
use warnings;
use Test::More;
use MetaCPAN::Web::Test;

test_psgi app, sub {
    my $cb = shift;
    ok( my $res = $cb->( GET "/recent" ), 'GET /recent' );
    is( $res->code, 200, 'code 200' );

    my $tx = tx($res);
    ok( my $release = $tx->_findv(
            '//div[@class="content"]/table[2]/tbody/tr[2]//a[1]/@href'),
        'contains a release'
    );
    ok( $res = $cb->( GET $release ), "GET $release" );
    is( $res->code, 200, 'code 200' );

};

done_testing;
