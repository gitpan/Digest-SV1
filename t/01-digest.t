#!/usr/bin/perl

use Test::More tests => 4;

BEGIN { use_ok( "Digest::SV1" ) }

my $ctx = Digest::SV1->new();

$ctx->add("Pack my box with five dozen jugs of liquor");

is(length($ctx->digest), 16, "digest came out with something");

is($ctx->hexdigest, "781ad9db62268b46a501510a44a3a67e",
   "hexdigest matches the reference values on this platform");

$ctx->add("!");

is($ctx->hexdigest, "271879c0a7a0386a4e173c49bd9544b3",
   "look, it works!");
