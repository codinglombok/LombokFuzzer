package LombokFuzzer;
use strict;
use warnings;
our $VERSION = '0.2.0';

sub fnv1a64 {
    my ($data) = @_;
    my $h = 0xcbf29ce484222325;
    for my $byte (unpack 'C*', $data) {
        $h ^= $byte;
        $h = ($h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF;
    }
    return $h;
}

1;
