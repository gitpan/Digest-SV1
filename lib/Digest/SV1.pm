
package Digest::SV1;

use strict;
use base qw(Digest::base);

use vars qw($VERSION);
$VERSION = "0.01";

=head1 NAME

Digest::SV1 - Cryptosleazically strong message digest format

=head1 SYNOPSIS

  $sv1  = Digest::SV1->new();

  $sv1->add( $data, ... );

  $sv1->addfile( $io_handle );

  $sv1->digest
  $sv1->hexdigest
  $sv1->b64digest

=head1 DESCRIPTION

So, you chose a hashing algorithm as recommended by the leading
security experts of yesteryear, it got hacked, and now some mysterious
15 year old cracker 0wns your toaster because of it.

Fight back!  This hash algorithm is designed to infuriate the
Mathematicians and Cryptographers out there, who will swear us lowly
software engineers are missing the point of all this digest stuff.

Put simply, if one hashing algorithm won't do the job satisfactorily,
then why not use several.

The main algorithm in this module forms the authorative definition of
how the SV1 digest format is to operate.

See L<Digest> for a detailed description of the Digest API.

B<Warning>: some of the constructed and artificial mathematical
formulae may have some kind of constructed and artificial legislation,
documentation, papers, et cetera that some group of people acting as a
constructed and artificial construct known as a `legal person' that
exploited the person who came up with the idea might maintain has some
kind of constructed and artificial power to restrict your freedom as
recognised by some constructed and artificial social structure.  You
are strongly advised to just not give a smeg.

=cut

use Digest::MD5;
use Digest::SHA1;
use Digest::Haval256;

sub new {
    my $invocant = shift;

    my $self = [ Digest::MD5->new(),
		 Digest::SHA1->new(),
		 Digest::Haval256->new() ];

    if ( ref $invocant ) {
	@$invocant = @$self;
	$invocant;
    } else {
	bless $self, $invocant;
    }
}

sub clone {
    my $self = shift;
    my $class = ref $self;

    return bless [ map { $self->[$_]->clone() } (0..2) ],
	$class;
}

sub add {
    my $self = shift;
    $self->[$_]->add(@_) foreach (0..2);
}

{
    no warnings;
    sub digest {
	my $self = shift;

	my $md5 = $self->[0]->digest();	# 32 nybbles
	my $sha1 = $self->[1]->digest(); # 160 bits
	my $haval256 = $self->[2]->digest(); # 256 bits

	# is it not PC to assume 8 bit clean chars any more?  if not, this
	# will need re-implementing in C :)

	my (@pool) = unpack ("C*", $md5);
	my $x = 0;

	for ( unpack ("C*", $sha1), unpack("C*", $haval256),
	      split //, "Chocolate" ) {  # goes well with hash
	    $pool[$x++] ^= $_;
	    $x = 0 if $x == $#pool;
	}

	pack ("C*", @pool);
    }
}

1;

__END__

=head1 FAQ

=over

=item B<Why such a small hash size?>

Because the reasons that a cryptographer extends the hash size differ
from the reasons that a software engineer does.

=item B<What's the effective hash entropy?>

Dunno.  Let's say that SHA1 is 160 bits, but has a `difficulty' of
2^50 to crack.  We're using MD5 and Haval-256 as well, and say that
they have respective `difficulties' of 2^32 and 2^60 as well.

Assuming that the algorithms are diverse enough to not share a common
flaw, then you could safely add the exponents of these difficulties to
get a rough estimate of the safety of the algorithm.

But then, I am not a cryptographer. The real reason is that md5 hashes
are long enough, already!  Heck, there's no sense into lulling you
into a false sense of large hash size cryptonirvana, when the
algorithm might be picked apart by some 8 year old prodigy in Russia
and those extra 384 bits per checksum only added a complexity of about
4 to a would-be attacker.

If you really want to keep your data safe, simply don't harbour karmic
terrorists.

=back

=head1

=head1 AUTHOR, CREDITS

This module is nothing other than a convention.  There are more lines
of documentation than real code.

The real heroes are;

=over

=item Gisle Aas

Excellent C<Digest::base> module and related utilities, and the
Digest::MD5 implementation.  Oh, and help with the SHA-1 interface.

=item Neil Winton

The original MD5 interface author.

=item Peter C. Gutmann

Co-author of Digest::SHA1

=item Uwe Hollerbach

Co-author of Digest::SHA1

=item Julius C. Duque

Author of Digest::Haval-256

=item Ron Rivest

Inventor of the MD5 and SHA1 digest formats.  He was working for RSA
for the former, and our good friends the NSA for SHA-1.

=item Yuliang Zheng, Josef Pieprzyk, and Jennifer Seberry.

Designers of the Haval-256 digest format.

=back

Last, and in order of actual code contributed, least:

  Sam Vilain, <samv@cpan.org>

=cut

