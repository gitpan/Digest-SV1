unless (eval "use Module::Build::Compat 0.02; 1" ) {
    print "This module requires Module::Build to install itself.\n";

    require ExtUtils::MakeMaker;
    my $yn = ExtUtils::MakeMaker::prompt
        ('  Install Module::Build now from CPAN?', 'y');

    unless ($yn =~ /^y/i) {
        die " *** Cannot install without Module::Build.  Exiting ...\n";
    }

    require Cwd;
    require File::Spec;
    require CPAN;

    # Save this 'cause CPAN will chdir all over the place.
    my $cwd = Cwd::cwd();
    my $makefile = File::Spec->rel2abs($0);

    CPAN::Shell->install('Module::Build::Compat')
	    or die " *** Cannot install without Module::Build.  Exiting ...\n";

    chdir $cwd or die "Cannot chdir() back to $cwd: $!";
    exec $^X, $makefile, @ARGV;  # Redo now that we have Module::Build
}

use lib 'lib';
Module::Build::Compat->run_build_pl(args => \@ARGV);
require Module::Build;
Module::Build::Compat->write_makefile(build_class => 'Module::Build');
