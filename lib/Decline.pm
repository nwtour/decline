package Decline;

use strict;
use utf8;

use File::Spec::Functions qw(catfile);
use DateTime;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::UserAgent;
use Time::HiRes qw(gettimeofday);
use Digest::SHA  qw(sha1_hex);
use SVG;
use GPG;
use LWP::Simple qw(mirror);
use LWP::Protocol::https;
use Archive::Zip;
use File::stat;

our $decline_dir;
our $version = 1;

my $index = {};

our $army = {
   "pikeman" => {
      ru => 'Пикеносец',
      1  => { attack => 1, defense => 1, movement => 3, cost => 5, tarif => 0.5 }
   },
   "guard" => {
      ru => 'Охранник',
      1  => { attack => 1, defense => 2, movement => 3, cost => 10, tarif => 0.8 }
   },
};

sub set_gpg_path {
   my $path = shift;

   if (open (FILE, '>', catfile ($decline_dir, 'key', 'gpg_path.txt'))) {

      print FILE $path;
      close (FILE);
   }
}

sub get_gpg_path {

   my $path;
   if (open (FILE, '<', catfile ($decline_dir, 'key', 'gpg_path.txt'))) {

      $path = $_ while (<FILE>);
      close (FILE);
      return $path;
   }

   foreach my $file ('C:\Program Files\GNU\GnuPG\gpg.exe', '/usr/bin/gpg' ) {

      next if ! -e $file;
      set_gpg_path ($file);
      return $file;
   }
   return undef;
}

sub gen_gpg_batch_file {

   my $batch_file = catfile ($decline_dir, 'key', 'gpg.batch.txt');

   if (open (FILE, '>', $batch_file)) {

      print FILE "%echo Generating a basic OpenPGP key\n";
      print FILE "Key-Type: RSA\n";
      print FILE "Name-Real: Test\n";
      print FILE "Name-Comment: Test\n";
      print FILE "Name-Email: joe\@foo.bar\n";
      print FILE "Expire-Date: 0\n";
      print FILE "%commit\n";
      print FILE "%echo done\n";
      close (FILE);
   }
   return $batch_file;
}

sub get_key_id {

   my $gpg = new GPG(debug => 0, homedir => catfile ($decline_dir, 'key'), gnupg_path => get_gpg_path ());

   my $keys = $gpg->list_sig();

   foreach my $k (@{$keys}) {

      return $k->{key_id} if exists $k->{sig} && $k->{key_id};
   }

   return undef;
}

#TODO
sub create_new_key {
   my $gpg_path = shift;

   my $homedir = catfile ($decline_dir, 'key');
   mkdir $homedir;

   system ( $gpg_path,
            '--homedir',
            $homedir,
            '--gen-key',
            '--batch',
            gen_gpg_batch_file ());

   if (get_key_id ()) {

      if (open (FILE, '>', catfile ($decline_dir, 'key', 'gpg_path.txt'))) {

         print FILE $gpg_path;
         close (FILE);
      }
   }
}

sub get_utc_hour {
   my (undef, undef, $utchour) = gmtime(time);

   return $utchour;
}

sub localtimezone_offset {
   my (undef, undef, $localhour) = localtime(time);
   my $utchour = get_utc_hour ();

   my $hour_offset = ($localhour - $utchour);
   $hour_offset += 24 if $hour_offset < 0;

   return $hour_offset;
}

sub get_utc_time {

   return int (DateTime->from_epoch (epoch => time)->set_time_zone ("UTC")->epoch ());
}

sub make_sorted_data {
   my $hashref = shift;

   my @sorted_keys = sort { $a cmp $b } (keys %{$hashref});
   my $i = 0;
   my $array_ref = [];
   while (exists $sorted_keys[$i]) {

      my $hr = $hashref->{ $sorted_keys[$i] };
      if (ref ($hr) eq 'HASH') {

         $hr = clone_data ($hr);
         $hr = make_sorted_data ($hr);
      }

      my @int_array = ($sorted_keys[$i]);
      push @int_array, $hr;
      push @{ $array_ref }, \@int_array;
      $i++;
   }
   return $array_ref;
}

sub get_json_and_sha1 {
   my $hashref = shift;

   my $json = encode_json (make_sorted_data ($hashref));
   return ($json, sha1_hex ($json));
}

sub part_json {
   my $arrayref = shift;

   my $hash_ref = {};
   foreach my $k (@{ $arrayref }) {
      my $val = $k->[1];
      if (ref ($val) eq 'ARRAY') {

         $val = clone_data ($val);
         $val = part_json ($val);
      }
      $hash_ref->{ $k->[0] } = $val;
   }
   return $hash_ref;
}

sub load_json {
   my $path = shift;
   my $json = '';
   if (open (FILE, '<', $path)) {
       while (<FILE>) {
          $json .= $_;
       }
       close (FILE);
       my $array_ref = decode_json ($json);
       return part_json ($array_ref);
   }
   return undef;
}

# Возвращаем unixtime в трёх частях
# первые пять символов: часть которая редко меняется (раз в сутки)
# последние пять символов: меняется каждую секунду
# первые три цифры микросекунд: действия редко происходят чаще чем тысячная секунды
sub entropy {
   my (undef, $microseconds) = gettimeofday;
   $microseconds = sprintf ("%06d", $microseconds);
   $microseconds = substr ($microseconds, 0, 3);
   my $dt = get_utc_time ();
   my $first = substr ($dt, 0, 5);
   my $second = substr ($dt, 5);
   return ($first,$second,$microseconds,$dt);
}

sub write_op {
   my ($hashref, $castle_id) = @_;

   my ($sub_dir, undef, $microseconds, $dt) = entropy ();
   my $full_dir = catfile ($decline_dir, 'data', $castle_id, $sub_dir);
   mkdir $full_dir if ! -d $full_dir;
   my ($json,undef) = get_json_and_sha1 ($hashref);
   if (open (FILE,'>',catfile ($full_dir, $dt . '.' . $microseconds))) {

      print FILE $json;
      close (FILE);
   }
}

sub write_castle_state {
   my ($json, $castle_id) = @_;

   if (open (FILE, '>', catfile ($decline_dir, 'data', $castle_id, 'state.json'))) {
      print FILE $json;
      close (FILE);
   }
   undef ($index);
   $index = {};
}

# TODO
sub create_new_coord {

   return (int (rand (100)), int (rand (100)), 1);   
}

sub load_castle {
   my $castle_id = shift;
   my $file_path = catfile ($decline_dir, 'data', $castle_id, 'state.json');
   return load_json ($file_path);
}

sub list_castles {
   my @list;
   foreach my $dir (glob (catfile ($decline_dir, 'data') . "/*")) {

      next if ! -d $dir;
      next if ! -e catfile ($dir, 'state.json');
      if ($dir =~ /(\d+)$/) {
         push @list, load_castle ($1);
      }
   }
   return @list;
}

sub list_my_castles {
   my $key = shift;

   my @list = grep {$_->{key} eq $key} list_castles ();
   return @list;
}

sub restrict_new_castle {
   my $key = shift;

   my @list = list_my_castles ($key);
   my $max_create_dt = 0;
   foreach my $c ( @list ) {
      $max_create_dt = $c->{dt} if $c->{dt} > $max_create_dt;
   }
   if ($max_create_dt < (get_utc_time () - (24*60*60))) {
      return 0;
   }
   return ($max_create_dt + (24*60*60) - get_utc_time ());
}

sub clone_data {
   my $ref = shift;
   my $VAR1;

   my $new_ref = eval (Data::Dumper::Dumper($ref));
   return $new_ref;
}

sub create_new_castle {
   my ($key,$hour) = @_;

   if (restrict_new_castle ($key)) {
      return 0;
   }

   my ($castle_id, $castle_dir);
   while (1) {

      $castle_id = int (rand (10000000));
      $castle_dir = catfile ($decline_dir, 'data', $castle_id);
      last if ! -d $castle_dir;
   }
   mkdir $castle_dir;
   my $dt = get_utc_time ();
   my ($x, $y, $mapid) = create_new_coord ();
   my $stepdt = $hour - localtimezone_offset ();
   $stepdt += 24 if $stepdt < 0;
   my $data = {
      key        => $key,
      dt         => $dt,
      id         => $castle_id,
      x          => $x,
      y          => $y,
      gold       => 50,
      population => 100,
      mapid      => $mapid,
      army       => {},
      stepdt     => $stepdt,
      laststep   => $dt,
   };
   my $op_data = clone_data ($data);
   my ($json, $sha1) = get_json_and_sha1 ($data);
   my (undef, $old_sha1) = get_json_and_sha1 ({});
   $op_data->{op} = "create_castle";
   $op_data->{new} = $sha1;
   $op_data->{old} = $old_sha1;
   write_op ($op_data, $castle_id);
   write_castle_state ($json, $castle_id);
   return $castle_id;
}

sub buy_army {
   my ($castle_id, $army_name) = @_;

   my $castle_ref = load_castle ($castle_id);
   return "Invalid castle id $castle_id" unless $castle_ref->{mapid};

   foreach my $arm ( keys %{ $army } ) {

      if ($arm eq $army_name) {

        return "Not enought gold" if $army->{$arm}{1}{cost} > $castle_ref->{gold};
        return "Not enought population" if $castle_ref->{population} < 10;

        my $clone_data = clone_data ($castle_ref);
        return "Internal error: $@" if ! exists $clone_data->{mapid};
        $clone_data->{gold} -= $army->{$arm}{1}{cost};
        $clone_data->{population} -= 10;
        my (undef,undef,$mcs,$bdt) = entropy ();
        return "Internal error: key exists" if exists $clone_data->{army}{ $bdt . $mcs };
        $clone_data->{army}{$bdt . $mcs} = {
           name       => $army_name,
           x          => $castle_ref->{x},
           y          => $castle_ref->{y},
           level      => 1,
           expirience => 0,
           movement   => $army->{$arm}{1}{movement},
           bdt        => $bdt,
           health     => 100
        };
        my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
        my ($json, $sha1) = get_json_and_sha1 ($clone_data);
        write_op ({op => 'buy', name => $arm, dt => $bdt, new => $sha1, old => $old_sha1}, $castle_id);
        write_castle_state ($json, $castle_id);
        return 0;
      }
   }
   return "Invalid name: $army_name";
}

sub coord_for_direction {
   my ($x,$y,$direction) = @_;

   $y++ if $direction =~ /s/;
   $y-- if $direction =~ /n/;
   $x-- if $direction =~ /w/;
   $x++ if $direction =~ /e/;

   return ($x,$y);
}

# 0 нельзя ходить 1 можно 2 можно аттаковать
sub has_move_army {
   my ($castle_id, $aid, $direction) = @_;

   return (0,"Invalid direction $direction") if $direction !~ /^(ne|nw|n|se|sw|s|w|e)$/;

   return (0,"Invalid army id") unless $aid;

   my $castle_ref = load_castle ($castle_id);
   my $mapid = $castle_ref->{mapid};
   return (0,"Invalid castle id $castle_id") unless $mapid;

   return (0,"Not enought movement points") unless $castle_ref->{army}{$aid}{movement};

   my ($x, $y) = coord_for_direction ($castle_ref->{army}{$aid}{x}, $castle_ref->{army}{$aid}{y}, $direction);

   my $dest = picture_by_coord ($mapid, $x, $y);
   if (! ref ($dest)) {

      return (0,"End of Kingdom") if $dest eq 0;
      return (1);
   }
   my (undef, $cid, $caid) = @{ $dest };
   if ($castle_id ne $cid) {

      return (2, $cid, $caid);
   }
   return (1) unless $caid; # To Castle
   return (0,"Busy");
}

sub has_move_army2 {
  my ($rc) = has_move_army (@_);
  return $rc;
}

sub move_army {
   my ($castle_id, $aid, $direction) = @_;

   my ($rc,$err,$naid) = has_move_army ($castle_id, $aid, $direction);
   return $err unless $rc;
   return "Unimplemented attack" if $rc == 2;

   my $castle_ref = load_castle ($castle_id);

   my $clone_data = clone_data ($castle_ref);
   return "Internal error: $@" if ! exists $clone_data->{mapid};
   $clone_data->{army}{$aid}{movement}--;

   ($clone_data->{army}{$aid}{x},$clone_data->{army}{$aid}{y}) =
      coord_for_direction ($clone_data->{army}{$aid}{x},$clone_data->{army}{$aid}{y},$direction);

   my (undef,$old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json,$sha1) = get_json_and_sha1 ($clone_data);
   write_op ({op => 'move', direction => $direction, dt => get_utc_time (), new => $sha1, old => $old_sha1}, $castle_id);
   write_castle_state ($json, $castle_id);
   return 0;
}

sub load_index {

   foreach my $castlehr (list_castles ()) {

      foreach my $aid (keys %{$castlehr->{army}}) {

         $index->{$castlehr->{mapid}}{$castlehr->{army}{$aid}{x}}{$castlehr->{army}{$aid}{y}}
            = [$castlehr->{army}{$aid}{name}, $castlehr->{id}, $aid];
      }

      $index->{$castlehr->{mapid}}{$castlehr->{x}}{$castlehr->{y}}
         = ["tower1", $castlehr->{id}];
   }
}

sub picture_by_coord {
   my ($mapid, $x, $y) = @_;

   if (! exists $index->{$mapid}) {

      load_index ();
   }

   return "0" if $x < 0;
   return "0" if $y < 0;

   return "0" if $x > ( $mapid * 100);
   return "0" if $y > ( $mapid * 100);

   return "5" if ! exists $index->{$mapid}{$x};
   return "5" if ! exists $index->{$mapid}{$x}{$y};

   return $index->{$mapid}{$x}{$y};
}

sub get_network_index {
   my $network = {};
   if (open (FILE, '<', catfile ($decline_dir, 'index', 'network.json'))) {

      my $data = '';
      $data .= $_ while (<FILE>);
      close (FILE);
      $network = decode_json ($data);
   }
   return $network;
}

sub write_network_index {
   my $network = shift;

   if (open (FILE,'>',catfile ($decline_dir, 'index', 'network.json'))) {

      print FILE encode_json ($network);
      close (FILE);
   }
}

# население плюс 2 процента каждые три часа
# деньги 4 процента от населения
sub increase_population {
   my ($castle_ref,$dt) = @_;

   my $population = $castle_ref->{population};
   my $gold = ($population / 3) / 8;
   if ($gold =~ /(\d+)\.(\d{2})/) {

      $gold = $1 . '.' . $2;
   }

   $population = int ($population / 50);
   $population += 1 unless $population;

   my $clone_data = clone_data ($castle_ref);
   $clone_data->{laststep} = $dt;
   $clone_data->{gold_increase} = $gold;
   $clone_data->{population_increase} = $population;   

   # TODO army tarif
   # TODO obrok

   $clone_data->{gold} += $gold;
   $clone_data->{population} += $population;

   my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json, $sha1) = get_json_and_sha1 ($clone_data);
   my $op = {
      op                  => 'increase_population',
      gold_increase       => $gold,
      population_increase => $population,
      dt                  => $dt,
      new                 => $sha1,
      old                 => $old_sha1
   };
   write_op ($op, $castle_ref->{id});
   write_castle_state ($json, $castle_ref->{id});
}

sub increase_movement {
   my ($castle_ref,$dt) = @_;

   my $clone_data = clone_data ($castle_ref);

   my $ops = {};
   foreach my $arm_id (keys %{$clone_data->{army}}) {

      my $name = $clone_data->{army}{$arm_id}{name};
      my $level = $clone_data->{army}{$arm_id}{level};

      if ($clone_data->{army}{$arm_id}{movement} ne $army->{$name}{$level}{movement}) {

         $clone_data->{army}{$arm_id}{movement} = $army->{$name}{$level}{movement};
         $ops->{$arm_id}{movement} = $army->{$name}{$level}{movement};
      }

      if ($clone_data->{army}{$arm_id}{health} ne 100) {

         $clone_data->{army}{$arm_id}{health} += 10;
         $clone_data->{army}{$arm_id}{health} = 100 if $clone_data->{army}{$arm_id}{health} > 100;
         $ops->{$arm_id}{heal} = $clone_data->{army}{$arm_id}{health};
      }
   }

   $clone_data->{laststep} = $dt;
   my (undef,$old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json,$sha1) = get_json_and_sha1 ($clone_data);
   write_op ({op => 'increase_movement', data => $ops, dt => $dt, new => $sha1, old => $old_sha1}, $castle_ref->{id});
   write_castle_state ($json, $castle_ref->{id});
}


sub local_update_castle {
   my $castlehr = shift;

   my $dt = get_utc_time ();
   if ($castlehr->{laststep} < ($dt - (60*60))) {
      my $basedt = ($castlehr->{laststep} > $castlehr->{dt} ? $castlehr->{laststep} : $castlehr->{dt});

      die "Error laststep > current date\n" if $basedt > $dt;

      $basedt += 1;

      while ($basedt < $dt) {

         my $datetime = DateTime->from_epoch (epoch => $basedt)->set_time_zone ("UTC");
         if ($datetime->second() != 0) {

            $basedt++;
            next;
         }
         if ($datetime->minute() == 0) {

            if ($datetime->hour_1() == $castlehr->{stepdt}) {

               increase_movement ($castlehr, $basedt);
            }
            if (! ($datetime->hour_1() % 3)) {

               increase_population ($castlehr, $basedt);
            }
            $basedt += (60*60);
         }
         else {

            $basedt += 60;
         }
      }
   }
}

sub local_updates {

   my $dt = get_utc_time ();
   foreach my $castlehr (list_castles ()) {

      local_update_castle ($castlehr);
      return if $dt < (get_utc_time () - 2);
   }
}

sub get_updates {

   local_updates ();
   return 0;

   my $network = get_network_index ();
   my $ua  = Mojo::UserAgent->new;
   $ua->max_redirects(0)->connect_timeout(3)->request_timeout(5)->inactivity_timeout(5);
   $network->{'http://78.78.78.78:8888'}{check} = get_utc_time ();
   write_network_index ($network);
   my $res = $ua->get('http://78.78.78.78:8888/ping');
   if ($res->res->code == 200) {

      $network->{'http://78.78.78.78:8888'}{success} = get_utc_time ();
      write_network_index ($network);
      return 1;
   }
   # https://metacpan.org/pod/Mojo::UserAgent
   return 0;

}

sub random_color {
   my @list = ('00', '33', '66', '99', 'CC', 'FF');

   my $color = '#';
   foreach (1 .. 3) {

      $color .= $list[int (rand (6))];
   }

   return $color;
}

sub generate_svg {
   my ($file,$key) = @_;

   my $svg = SVG->new (width => 1000, height => 1000);

   if ($file !~ /(\d+)\.svg/) {

      return $svg;
   }
   my $mapid = $1;

   my $multi = (1000 / ($mapid * 100));

   $svg->rectangle (x => 0, y => 0, width => 1000, height => 1000, id => 'rect', style => {stroke => 'black', 'fill-opacity' => 0});

   my %seen;

   foreach my $castle_ref (list_castles ()) {

      next if $castle_ref->{mapid} ne $mapid;
      my $color;
      my $ckey = $castle_ref->{key};

      foreach (1 .. 200) {
         if (exists $seen{$ckey}) {

            $color = $seen{$ckey};
            last;
         }
         $color = random_color ();
         if (! exists $seen{$color}) {

            $seen{$color}++;
            $seen{$ckey} = $color;
            last;
         }
      }
     
      my ($cid, $x, $y) = ($castle_ref->{id}, $castle_ref->{x}, $castle_ref->{y});
      my $z = $svg->group (id => "group$cid", style => {fill => $color});
      $z->circle (cx => ($x * $multi), cy => ($y * $multi), r => (1*$multi), id => "circle$cid");
      if ($key eq $ckey) {

         $svg->anchor (-href => "/public/castle/$cid",target => '_blank')->text (id => "t$cid", x => (($x*$multi) + $multi), y  => ($y*$multi), style => {'font' => 'Tahoma, Geneva, sans-serif', 'font-size' => 7})->cdata("${x}x${y} Без названия");
         next;
      }
      $svg->text (id => "t$cid", x => (($x*$multi) + $multi), y  => ($y*$multi), style => {'font' => 'Tahoma, Geneva, sans-serif', 'font-size' => 7})->cdata("${x}x${y}");
   }
   return $svg;
}

sub update_program_files {
   my ($full, $force) = @_;

   mkdir (catfile ($decline_dir, 'update'));

   my $archive_file = catfile ($decline_dir, "update", "master.zip");

   my $stat = stat ($archive_file);

   if (! defined ($stat) || $stat->mtime < (time - (60*60))) {

      mirror ('https://github.com/nwtour/decline/archive/master.zip', $archive_file);
   }

   my $result = {};
   return $result unless -f $archive_file;

   my $somezip = Archive::Zip->new;
   $somezip->read ($archive_file);

   foreach my $file ($somezip->members) {

      next unless $file->uncompressedSize;

      my @local_file = split (/\//, $file->fileName);
      shift (@local_file);

      my $stat = stat (catfile (@local_file));

      if (! defined ($stat)) {

         $result->{ catfile (@local_file) } = 1;
      }
      elsif (stat (catfile (@local_file))->size ne $file->uncompressedSize) {

         $result->{ catfile (@local_file) } = 1;
      }
      elsif ($full) {

         $result->{ catfile (@local_file) } = 0;
      }
   }
   return $result;
}

1;
