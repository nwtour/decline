package Decline;

use strict;
use utf8;

use File::Spec::Functions qw(catfile);
use DateTime;
use Mojo::JSON qw(decode_json encode_json);
use LWP::UserAgent;
use Mojo::UserAgent;
use Time::HiRes qw(gettimeofday);
use Digest::SHA  qw(sha1_hex);
use LWP::Simple qw(mirror);
use LWP::Protocol::https;
use Archive::Zip;
use File::stat;
use File::Copy qw(copy);

our $decline_dir;
our $version = 1;

my $geo_index = {};

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

sub get_decline_dir {
   die "\$decline_dir undefined\n" unless $decline_dir;
   die "Bad decline_dir\n" unless -d $decline_dir;
   return $decline_dir;
}

sub create_directory_tree {
   my ($castle_id, $subdir) = @_;

   my $d = get_decline_dir ();

   mkdir (catfile ($d, 'data'));
   mkdir (catfile (get_decline_dir (), 'data', 'remote'));
   mkdir (catfile ($d, 'key'));
   mkdir (catfile ($d, 'tmp'));

   if ($castle_id) {

      mkdir (catfile ($d, 'data', $castle_id));
      if ($subdir) {

         mkdir (catfile ($d, 'data', $castle_id, $subdir));
      }
   }
}

sub read_file_slurp {
   my $path = shift;
   my $result = '';

   if (open (FILE, '<', $path)) {

      $result .= $_ while (<FILE>);
      close (FILE);
   }
   return $result;
}

sub sha1_hex_file {
   my $path = shift;

   return sha1_hex (read_file_slurp ($path));
}

sub op_stringification {
   my $op = shift;

   $op = sprintf ("%07d", $op);
   return "$op";
}

sub set_gpg_path {
   my $path = shift;

   if (open (FILE, '>', catfile (get_decline_dir (), 'key', 'gpg_path.txt'))) {

      print FILE $path;
      close (FILE);
   }
}

sub get_gpg_path {

   my $path = read_file_slurp (catfile (get_decline_dir (), 'key', 'gpg_path.txt'));
   return $path if $path;

   foreach my $file ('C:\Program Files\GNU\GnuPG\gpg.exe', '/usr/bin/gpg' ) {

      next if ! -e $file;
      set_gpg_path ($file);
      return $file;
   }
   return undef;
}

sub gpg_add_key {
   my ($path, $key_id) = @_;

   my @list = (
      get_gpg_path (),
      '--homedir',
      catfile (get_decline_dir (), 'key'),
      '--batch',
      '--yes',
      '--import',
      $path
   );

   # warn join (' ', @list);
   my $rc = system (@list);
   my $destination = catfile (get_decline_dir (), 'data', "$key_id.asc");
   if (! $rc && ! -e $destination) {

      copy ($path, $destination);
   }
   return $rc;
}

sub gpg_create_signature {
   my ($source, $signature) = @_;

   my $rc = system (
      get_gpg_path (),
      '--homedir',
      catfile (get_decline_dir (), 'key'),
      '--batch',
      '--yes',
      '--output',
      $signature,
      '--detach-sig',
      $source
   );
   warn "gpg_create_signature $source -> $signature failed\n" if $?;
}

sub gpg_verify_signature {
   my ($source, $signature) = @_;

   my @list = (
      get_gpg_path (),
      '--homedir',
      catfile (get_decline_dir (), 'key'),
      '--batch',
      '--yes',
      '--verify',
      $signature,
      $source
   );

   # warn join (' ', @list, "\n");
   my $rc = system (@list);
   return $rc;
}

sub lock_data {
   my $file = shift;

   my $lockfile = catfile (get_decline_dir (), 'data', ($file || "file" ) . '.lck');

   if (-f $lockfile) {

      if (read_file_slurp ($lockfile) ne $$ || stat ($lockfile)->mtime < (time - (10*60))) {

         unlink ($lockfile);
      }
   }

   return undef if -f $lockfile;

   if (open (FILE, '>', $lockfile)) {

      print FILE $$;
      close (FILE);
      return 1;
   }
   return undef;
}

sub unlock_data {
   my $file = shift;

   my $lockfile = catfile (get_decline_dir (), 'data', ($file || "file" ) . '.lck');

   unlink ($lockfile) if -e $lockfile;
}

sub get_gpg_path_escape {
   my $file = get_gpg_path ();
   $file = '"' . $file . '"' if $file =~ /\s/;
   return $file;
}

sub gen_gpg_batch_file {

   my $batch_file = catfile (get_decline_dir (), 'key', 'gpg.batch.txt');

   my $rand = int (rand (100000000));

   if (open (FILE, '>', $batch_file)) {

      print FILE "%echo Generating a basic OpenPGP key\n";
      print FILE "Key-Type: RSA\n";
      print FILE "Name-Real: Test$rand\n";
      print FILE "Name-Comment: Test$rand\n";
      print FILE "Name-Email: joe$rand\@foo.bar\n";
      print FILE "Expire-Date: 0\n";
      print FILE "%commit\n";
      print FILE "%echo done\n";
      close (FILE);
   }
   return $batch_file;
}

sub keys_json_file {

   create_directory_tree ();

   return catfile (get_decline_dir (), 'data', 'keys.json');
}

sub clone_data {
   my $ref = shift;
   my $VAR1;

   my $new_ref = eval (Data::Dumper::Dumper($ref));
   return $new_ref;
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

sub get_json {
   my $hashref = shift;

   return encode_json (make_sorted_data ($hashref));
}

sub save_keys_json {
   my $result = shift;

   my $json = get_json ($result);
   if (open (FILE, '>', keys_json_file ())) {

      print FILE $json;
      close (FILE);
   }
}

sub set_key_attribute {
   my ($key, $attribute, $value) = @_;

   my $result = get_keys ();

   $result->{$key}{$attribute} = $value;

   save_keys_json ($result);
}

sub get_points {

   return load_json (catfile (get_decline_dir (), 'data', 'points.json'));
}

sub set_point_attribute {
   my ($point, $param, $value) = @_;

   create_directory_tree ();

   my $network = get_points ();

   $network->{$point}{$param} = $value;

   my $json = get_json ($network);

   if (open (FILE, '>', catfile (get_decline_dir (), 'data', 'points.json'))) {

      print FILE $json;
      close (FILE);
   }
}

sub get_my_address {
   my $hashref = get_points ();

   foreach my $point (keys %{$hashref}) {

      return $point if $hashref->{$point}{self};
   }
   return undef;
}

sub init_keys_json {

   my $result = {};
   $result = load_json (keys_json_file ()) if -f keys_json_file ();

   if (open (PIPE, '-|', get_gpg_path_escape () ." -a --homedir key --batch --no-comment --no-version --with-colons --list-keys")) {

      while (my $str = <PIPE>) {

         my @list = split (/:/, $str);
         if ($list[0] eq 'pub') {

            $result->{ $list[4] }{type} = $list[1];
            $result->{ $list[4] }{address} = get_my_address () if $list[1] eq 'u';
         }
      }
      close (PIPE);
   }

   save_keys_json ($result);
}

sub get_keys {

   my $result = load_json (keys_json_file ());
   return $result;
}

sub get_key_id {

   my $result = get_keys ();
   foreach my $k (keys %{$result}) {

      return $k if $result->{$k}{type} eq 'u';
   }
}

sub get_my_port {

   my $addr = get_my_address ();

   my $port = (split (':', $addr))[2];

   return ($port || 0);
}

sub create_new_key {
   my $gpg_path = shift;

   my $homedir = catfile (get_decline_dir (), 'key');

   my @list = (
      $gpg_path,
      '--homedir',
      $homedir,
      '--gen-key',
      '--batch',
      gen_gpg_batch_file ()
   );

   my $rc = system (@list);

   # warn join (' ', @list ) ." $rc $!\n";

   unlink (keys_json_file ());
   init_keys_json ();

   if (my $keyid = get_key_id ()) {

      @list = (
         $gpg_path,
         '--homedir',
         $homedir,
         '--export',
         '--armor',
         '--output',
         catfile (get_decline_dir (), 'data', "$keyid.asc")
      );
      $rc = system (@list);
      # warn join (' ', @list ) ." $rc $!\n";
      # TODO config.json
      if (open (FILE, '>', catfile (get_decline_dir (), 'key', 'gpg_path.txt'))) {

         print FILE $gpg_path;
         close (FILE);
      }
   }
   else {

      warn "Key generation failed\n";
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

sub get_json_and_sha1 {
   my $hashref = shift;

   my $json = get_json ($hashref);
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
   if (! -e $path) {

      #warn "load_json: Empty file $path\n";
      return {};
   }
   my $json = read_file_slurp ($path);
   my $array_ref = decode_json ($json);
   return part_json ($array_ref);
}

sub microseconds {
   my (undef, $microseconds) = gettimeofday;
   $microseconds = sprintf ("%06d", $microseconds);
   $microseconds = substr ($microseconds, 0, 3);
   return $microseconds;
}

sub parse_op_id {
   my $opid = shift;

   if ($opid && $opid =~ /^(\d{4})(\d{3})$/) {

      return ($1, $2);
   }
   return (0, undef);
}

sub write_op {
   my ($hashref, $castle_id) = @_;

   my ($sub_dir, $file) = parse_op_id ($hashref->{opid});

   if (! defined ($file)) {

      return (1, "Bad operation ID ($hashref->{op} -> $hashref->{opid})");
   }

   my $full_dir = catfile (get_decline_dir (), 'data', $castle_id, $sub_dir);
   create_directory_tree ($castle_id, $sub_dir);

   my $path_to_file = catfile ($full_dir, $file . '.json');

   return (1, "exist operation file $path_to_file") if -e $path_to_file;

   my $json = get_json ($hashref);
   if (open (FILE, '>', $path_to_file)) {

      print FILE $json;
      close (FILE);

      return (0, $path_to_file, catfile ($full_dir, $file . '.sig'));
   }
   return (1, "Unable open file $path_to_file");
}

sub write_castle_state {
   my ($json, $castle_id) = @_;

   if (open (FILE, '>', catfile (get_decline_dir (), 'data', $castle_id, 'state.json'))) {

      print FILE $json;
      close (FILE);
   }
   undef ($geo_index);
   $geo_index = {};
}

sub write_kingdom_state {

   my $result = {};
   foreach my $castle (sort {$a->{id} <=> $b->{id}} list_castles ()) {

      my (undef, $sha1) = get_json_and_sha1 ($castle);
      $result->{ $castle->{id} } = $sha1;
   }
   my $json = get_json ($result);
   if (open (FILE, '>', catfile (get_decline_dir (), 'data', 'kingdom.json'))) {

      print FILE $json;
      close (FILE);
   }
}

sub atomic_write_data {
   my ($castle_id, $json, $op) = @_;

   if (lock_data ()) {

      my ($rc, @list) = write_op ($op, $castle_id);
      if ($rc) {

         unlock_data ();
         return ($rc, $list[0]);
      }
      write_castle_state ($json, $castle_id);
      write_kingdom_state ();
      unlock_data ();
      return (0, @list);
   }
   return (1, "DATA directory locked");
}

# TODO
sub create_new_coord {

   return (int (rand (100)), int (rand (100)), 1);   
}

sub load_castle {
   my $castle_id = shift;
   my $file_path = catfile (get_decline_dir (), 'data', $castle_id, 'state.json');

   return load_json ($file_path);
}

sub is_my_castle {
   my ($key, $castle) = @_;

   return 0 if ! $key || ! $castle;
   return 0 if $key ne get_key_id ();
   return 0 if load_castle ($castle)->{key} ne $key;
   return 1;
}

sub list_castles {
   my @list;
   foreach my $dir (glob (catfile (get_decline_dir (), 'data') . "/*")) {

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
   foreach my $c (@list) {

      $max_create_dt = $c->{dt} if $c->{dt} > $max_create_dt;
   }
   if ($max_create_dt < (get_utc_time () - (24*60*60))) {

      return 0;
   }
   return ($max_create_dt + (24*60*60) - get_utc_time ());
}

sub unauthorised_create_castle {
   my $struct = shift;

   my $key       = $struct->{key};
   my $stepdt    = $struct->{stepdt};
   my $castle_id = $struct->{id};
   my $x         = $struct->{x};
   my $y         = $struct->{y};
   my $mapid     = $struct->{mapid};
   my $dt        = $struct->{dt};

   if (restrict_new_castle ($key)) {

      return (1, "No time for new castle");
   }

   my $castle_dir = catfile (get_decline_dir (), 'data', $castle_id);
   create_directory_tree ($castle_id);
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
      opid       => '0000000',
   };
   my $op_data = clone_data ($data);
   my ($json, $sha1) = get_json_and_sha1 ($data);
   my (undef, $old_sha1) = get_json_and_sha1 ({});
   $op_data->{op} = "unauthorised_create_castle";
   $op_data->{new} = $sha1;
   $op_data->{old} = $old_sha1;
   return atomic_write_data ($castle_id, $json, $op_data);
}

sub create_new_castle {
   my ($key, $hour) = @_;

   my ($castle_id);
   foreach (1 .. 10000) {

      $castle_id = int (rand (10000000));
      last if ! -d catfile (get_decline_dir (), 'data', $castle_id);
   }
   my $dt = get_utc_time ();
   my ($x, $y, $mapid) = create_new_coord ();
   my $stepdt = $hour - localtimezone_offset ();
   $stepdt += 24 if $stepdt < 0;
   my ($rc, @data) = unauthorised_create_castle ({
      key    => $key,
      stepdt => $stepdt,
      id     => $castle_id,
      x      => $x,
      y      => $y,
      mapid  => $mapid,
      dt     => $dt
   });

   gpg_create_signature (@data) if ! $rc;
   return $castle_id;
}

sub unauthorised_buy_army {
   my $struct = shift;

   my $castle_id = $struct->{id};
   my $dt        = $struct->{dt};
   my $army_id   = $struct->{army_id};
   my $army_name = $struct->{name};

   my $castle_ref = load_castle ($castle_id);
   return (1, "Invalid castle id $castle_id") unless $castle_ref->{mapid};

   return (1, "Invalid name: $army_name") if ! exists $army->{$army_name};

   return (1, "Not enought gold") if $army->{$army_name}{1}{cost} > $castle_ref->{gold};
   return (1, "Not enought population") if $castle_ref->{population} < 10;
   return (1, "Internal error: key exists") if exists $castle_ref->{army}{$army_id};

   my $clone_data = clone_data ($castle_ref);
   return (1, "Internal error: $@") if ! exists $clone_data->{mapid};
   $clone_data->{gold} -= $army->{$army_name}{1}{cost};
   $clone_data->{population} -= 10;
   $clone_data->{army}{$army_id} = {
      name       => $army_name,
      x          => $castle_ref->{x},
      y          => $castle_ref->{y},
      level      => 1,
      expirience => 0,
      movement   => $army->{$army_name}{1}{movement},
      bdt        => $dt,
      health     => 100
   };
   $clone_data->{opid} = op_stringification (++$clone_data->{opid});
   my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json, $sha1) = get_json_and_sha1 ($clone_data);

   return atomic_write_data ($castle_id, $json, {op => 'unauthorised_buy_army', army_id => $army_id, name => $army_name, dt => $dt, new => $sha1, old => $old_sha1, opid => $clone_data->{opid}});
}

sub buy_army {
   my ($castle_id, $army_name) = @_;

   my $castle_ref = load_castle ($castle_id);
   return "Invalid castle id $castle_id" unless $castle_ref->{mapid};

   my $dt  = get_utc_time ();
   my $mcs = microseconds ();
   foreach (1 .. 60) {

      last if ! exists $castle_ref->{army}{$dt . $mcs};
      sleep 1;
      $mcs = microseconds ();
      $dt  = get_utc_time ();
   }

   my ($rc, @data) = unauthorised_buy_army ({
      id => $castle_id,
      dt => $dt,
      army_id => $dt . $mcs,
      name => $army_name
   });

   return $data[0] if $rc;
   gpg_create_signature (@data);
   return 0;
}

sub coord_for_direction {
   my ($x, $y, $direction) = @_;

   $y++ if $direction =~ /s/;
   $y-- if $direction =~ /n/;
   $x-- if $direction =~ /w/;
   $x++ if $direction =~ /e/;

   return ($x, $y);
}

# 0 нельзя ходить 1 можно 2 можно аттаковать
sub has_move_army {
   my ($castle_id, $aid, $direction) = @_;

   return (0, "Invalid direction $direction") if $direction !~ /^(ne|nw|n|se|sw|s|w|e)$/;

   return (0, "Invalid army id") unless $aid;

   my $castle_ref = load_castle ($castle_id);
   my $mapid = $castle_ref->{mapid};
   return (0, "Invalid castle id $castle_id") unless $mapid;

   return (0, "Not enought movement points") unless $castle_ref->{army}{$aid}{movement};

   my ($x, $y) = coord_for_direction ($castle_ref->{army}{$aid}{x}, $castle_ref->{army}{$aid}{y}, $direction);

   my $dest = picture_by_coord ($mapid, $x, $y);
   if (! ref ($dest)) {

      return (0, "End of Kingdom") if $dest eq 0;
      return (1);
   }
   my (undef, $cid, $caid) = @{ $dest };
   if ($castle_id ne $cid) {

      return (2, $cid, $caid);
   }
   return (1) unless $caid; # To Castle
   return (0, "Busy");
}

sub has_move_army2 {
   my ($rc) = has_move_army (@_);
   return $rc;
}

sub unauthorised_move_army {
   my $struct = shift;

   my $castle_id = $struct->{id};
   my $army_id   = $struct->{army_id};
   my $direction = $struct->{direction};

   my ($rc, $err, undef) = has_move_army ($castle_id, $army_id, $direction);
   return (1, $err) unless $rc;
   return (1, "Unimplemented attack") if $rc == 2;

   my $castle_ref = load_castle ($castle_id);

   my $clone_data = clone_data ($castle_ref);
   return (1, "Internal error: $@") if ! exists $clone_data->{mapid};
   $clone_data->{army}{$army_id}{movement}--;

   ($clone_data->{army}{$army_id}{x}, $clone_data->{army}{$army_id}{y}) =
      coord_for_direction ($clone_data->{army}{$army_id}{x}, $clone_data->{army}{$army_id}{y}, $direction);

   $clone_data->{opid} = op_stringification (++$clone_data->{opid});
   my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json, $sha1) = get_json_and_sha1 ($clone_data);
   return atomic_write_data ($castle_id, $json, {
      op        => 'unauthorised_move_army',
      direction => $direction,
      dt        => $struct->{dt},
      new       => $sha1,
      old       => $old_sha1,
      army_id   => $army_id,
      opid      => $clone_data->{opid}
   });
}

sub move_army {
   my ($castle_id, $aid, $direction) = @_;

   my ($rc, @data) = unauthorised_move_army ({
      id        => $castle_id,
      dt        => get_utc_time (),
      army_id   => $aid,
      direction => $direction
   });

   return $data[0] if $rc;
   gpg_create_signature (@data);
   return 0;
}

sub load_geo_index {

   foreach my $castlehr (list_castles ()) {

      foreach my $aid (keys %{$castlehr->{army}}) {

         $geo_index->{ $castlehr->{mapid} }{ $castlehr->{army}{$aid}{x} }{ $castlehr->{army}{$aid}{y} }
            = [$castlehr->{army}{$aid}{name}, $castlehr->{id}, $aid];
      }

      $geo_index->{ $castlehr->{mapid} }{ $castlehr->{x} }{ $castlehr->{y} }
         = ["tower1", $castlehr->{id}];
   }
}

sub picture_by_coord {
   my ($mapid, $x, $y) = @_;

   if (! exists $geo_index->{$mapid}) {

      load_geo_index ();
   }

   return "0" if $x < 0;
   return "0" if $y < 0;

   return "0" if $x > ( $mapid * 100);
   return "0" if $y > ( $mapid * 100);

   return "5" if ! exists $geo_index->{$mapid}{$x};
   return "5" if ! exists $geo_index->{$mapid}{$x}{$y};

   return $geo_index->{$mapid}{$x}{$y};
}

sub unauthorised_increase_population {
   my $struct = shift;

   my $castle_ref = load_castle ($struct->{id});
   my $clone_data = clone_data ($castle_ref);
   $clone_data->{laststep}            = $struct->{dt};
   $clone_data->{gold_increase}       = sprintf ("%.2f", $struct->{gold_increase});
   $clone_data->{population_increase} = $struct->{population_increase};

   $clone_data->{gold}       += $struct->{gold_increase};
   $clone_data->{population} += $struct->{population_increase};

   $clone_data->{opid} = op_stringification (++$clone_data->{opid});

   my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json, $sha1) = get_json_and_sha1 ($clone_data);
   my $op = {
      op                  => 'unauthorised_increase_population',
      gold_increase       => $struct->{gold_increase},
      population_increase => $struct->{population_increase},
      dt                  => $struct->{dt},
      new                 => $sha1,
      old                 => $old_sha1,
      opid                => $clone_data->{opid},
   };
   return atomic_write_data ($struct->{id}, $json, $op);
}

# население плюс 2 процента каждые три часа
# деньги 4 процента от населения
sub increase_population {
   my ($castle_ref, $dt) = @_;

   my $population = $castle_ref->{population};
   my $gold = ($population / 3) / 8;
   $gold = sprintf ("%.2f", $gold);

   $population = int ($population / 50);
   $population = 1 unless $population;

   my ($rc, @data) = unauthorised_increase_population ({
      id                  => $castle_ref->{id},
      dt                  => $dt,
      gold_increase       => $gold,
      population_increase => $population,
   });
   warn $data[0] . "\n" if $rc;
   gpg_create_signature (@data) if ! $rc;
}

sub increase_movement {
   my ($castle_ref, $dt) = @_;

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
   $clone_data->{opid} = op_stringification (++$clone_data->{opid});
   my (undef, $old_sha1) = get_json_and_sha1 ($castle_ref);
   my ($json, $sha1) = get_json_and_sha1 ($clone_data);
   my ($rc, @data) = atomic_write_data ($castle_ref->{id}, $json, {
      op   => 'unauthorised_increase_movement',
      data => $ops,
      dt   => $dt,
      new  => $sha1,
      old  => $old_sha1,
      opid => $clone_data->{opid}
   });

   warn $data[0] . "\n" if $rc;
   gpg_create_signature (@data) if ! $rc;
}

sub increase_keepalive {
   my ($castle_ref, $dt) = @_;

   # TODO keepalive
}

sub local_update_castle {
   my $castlehr = shift;

   my $dt = get_utc_time ();
   return 0 if $castlehr->{laststep} > ($dt - (30*60));

   my $basedt = ($castlehr->{laststep} > $castlehr->{dt} ? $castlehr->{laststep} : $castlehr->{dt});

   die "Error laststep > current date\n" if $basedt > $dt;

   $basedt += 1;

   while ($basedt < $dt) {

      my $datetime = DateTime->from_epoch (epoch => $basedt)->set_time_zone ("UTC");
      if ($datetime->second() != 0) {

         $basedt++;
         next;
      }
      if ($datetime->minute() == 0 || $datetime->minute() == 30) {

         increase_keepalive ($castlehr, $basedt);
         $castlehr = load_castle ($castlehr->{id});
         if ($datetime->minute() == 30) {

            $basedt += (30*60);
            next;
         }

         if ($datetime->hour_1() == $castlehr->{stepdt}) {

            increase_movement ($castlehr, $basedt);
            $castlehr = load_castle ($castlehr->{id});
         }
         if (! ($datetime->hour_1() % 3)) {

            increase_population ($castlehr, $basedt);
            $castlehr = load_castle ($castlehr->{id});
         }
         $basedt += (30*60);
      }
      else {

         $basedt += 60;
      }
   }
}

sub local_updates {

   my $dt = get_utc_time ();
   my $key = get_key_id ();
   foreach my $castlehr (list_my_castles ($key)) {

      local_update_castle ($castlehr);
      return if $dt < (get_utc_time () - 2);
   }
}

sub gen_address {
   my $template = shift;

   return ('', "Empty address") unless $template;

   return ('', "Bad template" ) if $template !~ /^http:(\d+)\.(\d+)\.(\d+)\.(\d+):(\d+)$/;

   return (join ('', 'http://', (split (':', $template))[1], ':', (split (':', $template))[2]), '');
}

sub unauthorised_router {
   my ($castle_id, $op_file) = @_;
   my $data = Decline::load_json ($op_file);

   my $cmd = $data->{op};
   $data->{id} = int ($castle_id);

   my ($code, $errstr);

   if ($cmd eq 'unauthorised_create_castle') {

      ($code, $errstr) = Decline::unauthorised_create_castle ($data);
   }
   elsif ($cmd eq 'unauthorised_buy_army') {

      ($code, $errstr) = Decline::unauthorised_buy_army ($data);
   }
   elsif ($cmd eq 'unauthorised_move_army') {

      ($code, $errstr) = Decline::unauthorised_move_army ($data);
   }
   elsif ($cmd eq 'unauthorised_increase_population') {

      ($code, $errstr) = Decline::unauthorised_increase_population ($data);
   }
   else {

      return (1, "Unimplemented $cmd", $cmd);
   }
   return ($code, $errstr, $cmd, $data->{dt}, $data->{new});
}

sub sync_castle {
   my ($type, $castle_id, $point_template, $needed_sha1) = @_;

   my $ua = LWP::UserAgent->new;
   $ua->timeout (20);

   my ($subdir, $file) = ('0000', '000');

   if ($type eq "update") {

      my $obj = load_castle ($castle_id);
      ($subdir, $file) = parse_op_id (++$obj->{opid});
      if (! defined ($file)) {

         die "Unable load last operation id for castle $castle_id\n";
      }
   }
   my ($url) = gen_address ($point_template);

   warn "Castle $castle_id : $type ($file)\n";
   my $json_file = catfile (get_decline_dir (), 'tmp', "$file.json");
   my $sig_file = catfile (get_decline_dir (), 'tmp', "$file.sig");
   my $res1 = $ua->mirror ("$url/$castle_id/$subdir/$file.json", $json_file);
   my $res2 = $ua->mirror ("$url/$castle_id/$subdir/$file.sig",  $sig_file);

   if ($res1->code !~ /^(2|3)/ || $res2->code !~ /^(2|3)/) {

      my $real_sha1 = sha1_hex_file (catfile (get_decline_dir (), 'data', $castle_id, 'state.json'));
      if ($real_sha1 ne $needed_sha1) {

         warn "Not found next file $file (but kingdom incomplete) $real_sha1 $needed_sha1\n";
      }
      return 0;
   }

   if (my $rc = Decline::gpg_verify_signature ($json_file, $sig_file)) {

      unlink ($sig_file);
      unlink ($json_file);
      warn "failed verification $file.sig $castle_id\n";
      return 0;
   }

   my ($code, $errstr, $cmd, $update_date, $oplog_sha1) = unauthorised_router ($castle_id, $json_file);

   if ($code) {

      warn "$cmd code: $code errstr: $errstr\n";
      return 0;
   }
   my $dest = catfile (get_decline_dir (), 'data', $castle_id, $subdir, "$file.sig");
   if (! copy ($sig_file, $dest)) {

      warn "Copy $sig_file to $dest failed: $!\n";
   }
   unlink ($sig_file);
   unlink ($json_file);

   my $real_sha1 = sha1_hex_file (catfile (get_decline_dir (), 'data', $castle_id, 'state.json'));

   if ($real_sha1 eq $oplog_sha1) {

      Decline::set_point_attribute ($point_template, 'transferdt', $update_date);
      if ($needed_sha1 eq $oplog_sha1) {

         warn "CONGRATULATION TRANSFER\n";
      }
      else {

         warn "Transfer valid, but kingdom incomplete\n";
      }
   }
   else {

      warn "ERROR Transfer $castle_id : needed: $needed_sha1 oplog: $oplog_sha1 real: $real_sha1\n";
   }
   return $update_date;
}

sub sync_castles {

   my $points = get_points ();

   my $ua = LWP::UserAgent->new;
   $ua->timeout (20);

   foreach my $p (keys %{$points}) {

      my ($url, $errstr) = gen_address ($p);
      next if $p eq get_my_address ();
      next if ($points->{$p}{livedt} || 0) < get_utc_time () - 20;
      next if ! $url;

      my $response = $ua->mirror ("$url/kingdom.json", catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json"));

      if ($response->code !~ /^(2|3)/) {

         warn "Debug: $url/kingdom.json : " . $response->code . "\n";
         next;
      }

      next if (Decline::sha1_hex_file (catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json")) eq
               Decline::sha1_hex_file (catfile (get_decline_dir (), 'data', "kingdom.json")));

      my $old_struct = Decline::load_json (catfile (get_decline_dir (), 'data', "kingdom.json"));
      my $new_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json"));

      die "Bad keys.json\n" if ref ($new_struct) ne 'HASH';

      # TODO sort by date
      foreach my $k (keys %{$new_struct}) {

         # sha1 in kingdom.json == state.json: kingdom.json incomplete another side
         next if $new_struct->{$k} eq sha1_hex_file (catfile (get_decline_dir (), 'data', $k, 'state.json'));

         if (my $dt = Decline::sync_castle ((exists $old_struct->{$k} ? "update" : "create"), $k, $p, $new_struct->{$k})) {

            return $dt;
         }
      }
   }
   return 0;
}

sub sync_keys {

   my $points = get_points ();

   my $ua = LWP::UserAgent->new;
   $ua->timeout (20);

   create_directory_tree ();

   foreach my $p (keys %{$points}) {

      my ($url, $errstr) = gen_address ($p);

      next if $p eq get_my_address ();
      next if ! $url;
      next if ($points->{$p}{livedt} || 0) < get_utc_time () - 20;

      my $response = $ua->mirror ($url . '/keys.json', catfile (get_decline_dir (), 'data', 'remote', "$p.keys.json"));

      if ($response->code !~ /^(2|3)/) {

         warn "Debug $url : " . $response->code . "\n";
         next;
      }

      next if (Decline::sha1_hex_file (catfile (get_decline_dir (), 'data', 'remote', "$p.keys.json")) eq
               Decline::sha1_hex_file (catfile (get_decline_dir (), 'data', 'keys.json')));

      warn "$p exchange keys.json\n";

      my $old_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'keys.json'));
      my $new_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'remote', "$p.keys.json"));

      die "Bad keys.json\n" if ref ($new_struct) ne 'HASH';

      foreach my $k (keys %{$new_struct}) {

         next if exists $old_struct->{$k};

         warn "New key $k\n";
         $response = $ua->mirror ( $url . "/$k.asc", catfile (get_decline_dir (), 'data', "$k.asc"));
         if ($response->code =~ /^(2|3)/) {

            my ($rc, $err) = gen_address ($new_struct->{$k}{address});
            if ($rc) {

               Decline::gpg_add_key (catfile (get_decline_dir (), 'data', "$k.asc"), $k);
               Decline::init_keys_json ();
               Decline::set_key_attribute ($k, 'address', $new_struct->{$k}{address});
               Decline::set_point_attribute ($new_struct->{$k}{address}, 'self', 0);
               # TODO verify key (email)
            }
            else {

               warn "Bad address in $k.keys.json : $err\n";
               next;
            }
         }
      }
   }
}

sub prepare_points {

   my $points = get_points ();

   foreach my $p (keys %{$points}) {

      next if $p eq get_my_address ();
      my ($url, $errstr) = gen_address ($p);
      if (! $url) {

         warn "INVALID POINT $p\n";
         next;
      }

      next if ($points->{$p}{checkdt} || 0) > get_utc_time () - 20;
      Decline::set_point_attribute ($p, 'checkdt', Decline::get_utc_time ());

      my $r = Mojo::UserAgent->new->max_redirects(0)->connect_timeout(5)->request_timeout(10)->inactivity_timeout(10)->get ($url . '/keys.json');
      if ($r->res->code == 200) {

         warn "$url IS LIVE\n";
         Decline::set_point_attribute ($p, 'livedt', Decline::get_utc_time ());
      }
   }
}

sub remote_updates {
   prepare_points ();
   sync_keys ();
   my $dt = sync_castles ();
   return $dt;
}

sub get_updates {

   local_updates  ();
   my $dt = remote_updates ();
   return $dt;
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
   my ($mapid, $key) = @_;

   my $multi = (1000 / ($mapid * 100));

   my (%seen, $result) = ((), []);

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

      push @{ $result }, {
         id       => $castle_ref->{id},
         name     => $castle_ref->{x} . 'x' . $castle_ref->{y} . ($key eq $ckey ? " Без названия" : ''),
         color    => $color,
         radius   => (1*$multi),
         x_offset => $multi,
         x        => ($castle_ref->{x} * $multi),
         y        => ($castle_ref->{y} * $multi)
      };
   }
   return $result;
}

sub update_program_files {
   my ($full, $sha1) = @_;

   create_directory_tree ();

   my $archive_file = catfile (get_decline_dir (), 'data', 'remote', "master.zip");

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

      if ($sha1 && sha1_hex ($file->fileName) eq $sha1) {

         $somezip->extractMember ($file->fileName, catfile (@local_file));
      }

      my $stat = stat (catfile (@local_file));

      if (! defined ($stat)) {

         $result->{ catfile (@local_file) } = sha1_hex ($file->fileName);
      }
      elsif (stat (catfile (@local_file))->size ne $file->uncompressedSize) {

         $result->{ catfile (@local_file) } = sha1_hex ($file->fileName);
      }
      elsif ($full) {

         $result->{ catfile (@local_file) } = undef;
      }
   }
   return $result;
}

1;
