#!/usr/bin/perl
#

use strict;

use Module::Build;
Module::Build->new
    ( module_name => 'Digest::SV1',
      requires => {
		   'Digest'           => 0,
		   'Digest::SHA1'     => 0,
		   'Digest::MD5'      => 0,
		   'Digest::Haval256' => 0,
		  },
      license => 'perl',
      #create_makefile_pl => 'passthrough'
    )->create_build_script;
