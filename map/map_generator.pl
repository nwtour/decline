use strict;

use Image::Magick;
use Mojo::JSON qw(decode_json encode_json);
use Decline;

my $p = new Image::Magick;
$p->Read ("map.png");

my $val = {
          '0.88 0.87 0.87' => 7,
          '0.53 0.89 0.89' => 3,
          '0.55 0.53 0.53' => 8,
          '0.95 0.94 0.94' => 5,
          '0.28 0.26 0.26' => 9,
          '0.69 0.67 0.67' => 6,
          '0.00 0.00 0.00' => 10,
          '1.00 1.00 1.00' => 4,
          '1.00 0.00 0.00' => 0,
};

my $coord = {};

foreach my $y (1 .. 100) {

   foreach my $x (1 .. 100) {

      my @pixels = $p->GetPixel (x => $x, y => $y);

      my $color = join (' ', sprintf ("%0.2f", $pixels[0]), sprintf ("%0.2f", $pixels[1]), sprintf ("%0.2f", $pixels[1]));

      warn "Not found $color\n" if ! exists $val->{$color};

      $coord->{ $x . 'x' . $y } = $val->{$color};

   }
}

Decline::write_file_slurp (encode_json ($coord), 'map.json');

