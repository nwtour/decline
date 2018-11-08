package Decline;

use strict;
use utf8;
use warnings "all";

use File::Spec::Functions qw(catfile);
use DateTime;
use Mojo::JSON qw(decode_json encode_json);
use LWP::UserAgent;
use Mojo::UserAgent;
use Time::HiRes qw(gettimeofday);
use LWP::Simple qw(mirror);
use LWP::Protocol::https;
use Archive::Zip;
use File::stat;
use File::Copy qw(copy);
use File::Basename qw(basename);
use Crypt::Digest::SHA1 qw(sha1_hex sha1_file_hex);  # package CryptX
use Crypt::PK::RSA;                                  # package CryptX
use Storable qw(dclone);

our $decline_dir;
our $VERSION = 1;
our $max_map_id = 0;

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
   "archer" => {
      ru => 'Лучник',
      1  => { attack => 2, defense => 1, movement => 3, cost => 10, tarif => 0.8 }
   },
   "cavalry" => {
      ru => 'Разведчик',
      1  => { attack => 2, defense => 1, movement => 6, cost => 30, tarif => 2 }
   },
   "balista" => {
      ru => 'Балиста',
      1  => { attack => 4, defense => 1, movement => 3, cost => 40, tarif => 1.5 }
   },
   "heavy" => {
      ru => 'Тяжелый рыцать',
      1  => { attack => 3, defense => 5, movement => 3, cost => 60, tarif => 3.5 }
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
   return 1;
}

sub write_file_slurp {
   my ($data, $path, $binmode) = @_;

   if (open (my $file, '>', $path)) {

      binmode ($file) if $binmode;
      print {$file} $data;
      close ($file);
      return 0;
   }
   return 1;
}

sub read_file_slurp {
   my ($path, $binmode) = @_;
   my $result = '';

   if (open (my $file, '<', $path)) {

      binmode ($file) if $binmode;
      $result .= $_ while (<$file>);
      close ($file);
   }
   return $result;
}

sub add_key {
   my ($path, $key_id) = @_;

   my $destination = catfile (get_decline_dir (), 'data', "$key_id.asc");
   if (-e $destination) {

      return 1;
   }
   elsif (-f $path && sha1_file_hex ($path) eq $key_id) {

      if (! copy ($path, $destination)) {

         warn "failed copy $path to $destination: $!\n";
         return 2;
      }
      return 0;
   }
   return 3 if ! -f $path;
   return 4;
}

sub kingdom_json_file {
   my $extention = shift;

   return catfile (get_decline_dir (), 'data', join ('', 'kingdom.json', ($extention || '')));
}

sub castle_state_file {
   my ($castle_id, $extention) = @_;

   die "invalid usage\n" unless $castle_id;

   return catfile (get_decline_dir (), 'data', $castle_id, join ('', 'state.json', ($extention || '')));
}

sub rollback_save_state {
   my $castle_id = shift;

   my $result = [
      {
         source => kingdom_json_file (),
         bak    => kingdom_json_file ('.bak'),
         sha1   => sha1_file_hex (kingdom_json_file ())
      },
      {
         source => castle_state_file ($castle_id),
         bak    => castle_state_file ($castle_id, '.bak'),
         sha1   => sha1_file_hex (castle_state_file ($castle_id))
      },
   ];

   return $result;
}

sub rollback_restore {
   my ($saved_state, $source, $signature) = @_;

   die "Bad rollback_state\n" if ref ($saved_state) ne 'ARRAY';

   foreach my $file (@{$saved_state}) {

      my $sha1_bak = sha1_file_hex ($file->{bak});
      if ($file->{sha1} eq sha1_file_hex ($file->{bak})) {

         if (! copy ($file->{bak}, $file->{source})) {

            warn $file->{bak} . " failed copy $!\n";
         }
         warn $file->{source} . " restored\n";
         next;
      }
      warn $file->{source} . " " . $file->{sha1} . "<=> $sha1_bak error restore!\n";
   }
   unlink ($source);
   unlink ($signature);
   return "rollback operation " . basename ($source);
}

sub gpg_create_signature {
   my ($source, $signature) = @_;

   my $pk = Crypt::PK::RSA->new (catfile (get_decline_dir (), 'key', 'key.private'));
   my $sig = $pk->sign_message (read_file_slurp ($source));

   write_file_slurp ($sig, $signature, 1);

   return 0;
}

sub gpg_verify_signature {
   my ($key, $source, $signature) = @_;

   my $pk = Crypt::PK::RSA->new (catfile (get_decline_dir (), 'data', "$key.asc"));
   my $verify = $pk->verify_message (read_file_slurp ($signature, 1), read_file_slurp ($source));
   return ($verify ? 0 : 1);
}

sub lock_data {
   my $file = shift;

   my $lockfile = catfile (get_decline_dir (), 'data', ($file || "file" ) . '.lck');

   if (-f $lockfile) {

      if (read_file_slurp ($lockfile) ne $$ || stat ($lockfile)->mtime < (time - (10*60))) {

         unlink ($lockfile);
      }
   }

   return 0 if -f $lockfile;

   return (write_file_slurp ($$, $lockfile) ? 0 : 1);
}

sub unlock_data {
   my $file = shift;

   my $lockfile = catfile (get_decline_dir (), 'data', ($file || "file" ) . '.lck');

   unlink ($lockfile) if -e $lockfile;
   return 1;
}

sub keys_json_file {

   create_directory_tree ();

   return catfile (get_decline_dir (), 'data', 'keys.json');
}

sub make_sorted_data {
   my $hashref = shift;

   my @sorted_keys = sort { $a cmp $b } (keys %{$hashref});
   my $i = 0;
   my $array_ref = [];
   while (exists $sorted_keys[$i]) {

      my $hr = $hashref->{ $sorted_keys[$i] };
      if (ref ($hr) eq 'HASH') {

         $hr = dclone ($hr);
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
   return write_file_slurp (get_json ($result), keys_json_file ());
}

sub set_key_attribute {
   my ($key, $attribute, $value) = @_;

   my $result = get_keys ();

   $result->{$key}{$attribute} = $value;

   return save_keys_json ($result);
}

sub get_points {

   return load_json (catfile (get_decline_dir (), 'data', 'points.json'));
}

sub set_point_attribute {
   my ($point, $param, $value) = @_;

   create_directory_tree ();

   my $network = get_points ();

   $network->{$point}{$param} = $value;

   my $j = get_json ($network);

   return write_file_slurp ($j, catfile (get_decline_dir (), 'data', 'points.json'));
}

sub get_my_address {
   my $hashref = get_points ();

   foreach my $point (keys %{$hashref}) {

      return $point if $hashref->{$point}{self};
   }
   return '';
}

sub init_keys_json {

   my $result = {};
   $result = load_json (keys_json_file ()) if -f keys_json_file ();

   my $key_sha1 = sha1_file_hex (catfile (get_decline_dir (), 'key', 'key.public'));

   foreach my $file (grep { -f $_ } glob (catfile (get_decline_dir (), 'data') . "/*")) {

      if (basename ($file) =~ /(\w+)\.asc$/) {

         my $key = $1;
         next if exists $result->{$key};
         if (sha1_file_hex ($file) eq $key_sha1) {

            $result->{$key} = { type => 'u', address => get_my_address () };
            next;
         }
         $result->{$key}{type} = '-';
      }
   }
   return save_keys_json ($result);
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
   return '';
}

sub key_for_point {
   my $point = shift;

   my $keys = get_keys ();
   foreach my $k (keys %{$keys}) {

      return $k if exists $keys->{$k}{address} && $keys->{$k}{address} eq $point;
   }
   return '';
}

sub get_my_port {

   my $addr = get_my_address ();

   my $port = (split (':', $addr))[2];

   return ($port || 0);
}

sub create_new_key {

   my $dest = catfile (get_decline_dir (), 'key', 'key');

   my $pk = Crypt::PK::RSA->new();
      $pk->generate_key(256, 65537);
   write_file_slurp ($pk->export_key_der ('public' ), "$dest.public",  1);
   write_file_slurp ($pk->export_key_der ('private'), "$dest.private", 1);

   unlink (keys_json_file ());
   copy (
      $dest . '.public',
      catfile (get_decline_dir (), 'data', sha1_file_hex ($dest . '.public') . '.asc')
   );
   return init_keys_json ();
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

sub json_with_fixed_datatypes {
   my $hashref = shift;

   my $types = {
      gold          => "%.2f",
      gold_increase => "%.2f",
      opid          => "%d",
   };

   foreach my $p (keys %{$types}) {

      next if ! exists $hashref->{$p};
      $hashref->{$p} = sprintf ($types->{$p}, $hashref->{$p});
   }

   return get_json_and_sha1 ($hashref);
}

sub part_json {
   my $arrayref = shift;

   my $hash_ref = {};
   foreach my $k (@{ $arrayref }) {
      my $val = $k->[1];
      if (ref ($val) eq 'ARRAY') {

         $val = dclone ($val);
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

# 0 -> ('0000' '000'), 5523 -> ('0005', '523')
sub parse_op_id {
   my $opid = shift;

   return (0, undef) if ! defined ($opid);

   return (
      sprintf ("%04s", int ($opid / 1000)),
      sprintf ("%03s", substr ($opid, -3))
   );
}

sub write_op {
   my ($hashref, $castle_id) = @_;

   my ($sub_dir, $file) = parse_op_id ($hashref->{opid});

   return (1, "Bad operation ID ($hashref->{op} -> $hashref->{opid})") if ! defined ($file);

   my $full_dir = catfile (get_decline_dir (), 'data', $castle_id, $sub_dir);
   create_directory_tree ($castle_id, $sub_dir);

   my $path_to_file = catfile ($full_dir, $file . '.json');

   return (1, "exist operation file $path_to_file") if -e $path_to_file;

   my $json = get_json ($hashref);
   if (write_file_slurp (get_json ($hashref), $path_to_file)) {

      return (1, "Unable open file $path_to_file");
   }
   return (0, $path_to_file, catfile ($full_dir, $file . '.sig'));
}

sub load_castle {
   my $castle_id = shift;

   return load_json (castle_state_file ($castle_id));
}

sub write_castle_state {
   my ($json, $castle_id) = @_;

   if (-e castle_state_file ($castle_id) && ! copy (castle_state_file ($castle_id), castle_state_file ($castle_id, '.bak'))) {

      warn "Unable state.json backup file ($castle_id) $!\n";
   }

   write_file_slurp ($json, castle_state_file ($castle_id));

   my $castle_ref = load_castle ($castle_id);

   if (ref ($castle_ref) eq 'HASH' && defined $castle_ref->{mapid}) {

      delete $geo_index->{ $castle_ref->{mapid} };
      return 1;
   }

   return 0;
}

# TODO cache
sub list_castles {
   my @list;
   foreach my $dir (glob (catfile (get_decline_dir (), 'data') . "/*")) {

      next if ! -d $dir;
      next if ! -e catfile ($dir, 'state.json');
      if ($dir =~ /(\d+)$/) {

         my $castle_ref = load_castle ($1);
         $max_map_id = $castle_ref->{mapid} if defined ($castle_ref->{mapid}) && $castle_ref->{mapid} > $max_map_id;
         push @list, $castle_ref;
      }
   }
   return @list;
}

sub get_max_map_id {

   return $max_map_id if $max_map_id;
   list_castles ();
   return $max_map_id;
}

sub write_kingdom_state {

   my $result = {};
   foreach my $castle (sort {$a->{id} <=> $b->{id}} list_castles ()) {

      my (undef, $sha1) = get_json_and_sha1 ($castle);
      $result->{ $castle->{id} } = $sha1;
   }

   if (-e kingdom_json_file () && ! copy (kingdom_json_file (), kingdom_json_file ('.bak'))) {

      warn "Unable kingdom.json backup file $!\n";
   }

   return write_file_slurp (get_json ($result), kingdom_json_file ());
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

sub is_my_castle {
   my ($key, $castle) = @_;

   return 0 if ! $key || ! $castle;
   return 0 if $key ne get_key_id ();
   return 0 if load_castle ($castle)->{key} ne $key;
   return 1;
}

sub list_my_castles {
   my $key = shift;

   my @list = grep {$_->{key} eq $key} list_castles ();
   return @list;
}

# Create random coordinates and return current MapId for new castle.
sub create_new_coord {
   my $plus = shift;

   my $cnt = scalar (list_my_castles (get_key_id ()));

   foreach my $cm (1 .. 100) {

      my $limit = $cm * $cm; # 1 4 9 16 25 36 49 64

      next if $cnt >= $limit;

      $cm += $plus; # If on current map high density
      return (int (rand ($cm * 100)), int (rand ($cm * 100)), $cm);
   }
   warn "Internal error, cannot create new coord\n";
   return (0, 0, 0);
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

sub load_geo_index {
   my $mapid = shift;

   my $i = 0;

   if (-f catfile (get_decline_dir (), 'map', 'map.json')) {

      my $hashref = decode_json (read_file_slurp (catfile (get_decline_dir (), 'map', 'map.json')));

      foreach my $k (keys %{$hashref}) {

         my ($x, $y) = $k =~ m/(\d+)x(\d+)/;
         foreach my $mid_x (1 .. $mapid) {

            $mid_x--;
            foreach my $mid_y (1 .. $mapid) {

               $mid_y--;
               $geo_index->{$mapid}{ ($x + ($mid_x * 100)) }{ ($y + ($mid_y * 100)) } = $hashref->{$k};
            }
         }
      }
   }

   foreach my $castlehr (list_castles ()) {

      next if $castlehr->{mapid} ne $mapid;

      foreach my $aid (keys %{$castlehr->{army}}) {

         $geo_index->{$mapid}{ $castlehr->{army}{$aid}{x} }{ $castlehr->{army}{$aid}{y} }
            = [$castlehr->{army}{$aid}{name}, $castlehr->{id}, $aid];
         $i++;
      }

      $geo_index->{$mapid}{ $castlehr->{x} }{ $castlehr->{y} }
         = ["tower1", $castlehr->{id}];
   }
   return $i;
}

sub picture_by_coord {
   my ($mapid, $x, $y) = @_;

   if (! exists $geo_index->{$mapid}) {

      load_geo_index ($mapid);
   }

   return 0 if $x < 0;
   return 0 if $y < 0;

   return 0 if $x > ($mapid * 100);
   return 0 if $y > ($mapid * 100);

   return 5 if ! exists $geo_index->{$mapid}{$x};
   return 5 if ! exists $geo_index->{$mapid}{$x}{$y};

   return $geo_index->{$mapid}{$x}{$y};
}

sub is_free_coord {
   my @list = @_;

   my $r = picture_by_coord (@list);

   return 1 if ! ref ($r) && $r > 0 && $r < 11;
   return 0;
}

sub is_free_district {
   my ($mapid, $x, $y) = @_;

   return 0 if ! is_free_coord ($mapid,       $x,  $y     );
   return 0 if ! is_free_coord ($mapid, ($x + 1),  $y     );
   return 0 if ! is_free_coord ($mapid, ($x - 1),  $y     );

   return 0 if ! is_free_coord ($mapid,       $x, ($y - 1));
   return 0 if ! is_free_coord ($mapid, ($x + 1), ($y - 1));
   return 0 if ! is_free_coord ($mapid, ($x - 1), ($y - 1));

   return 0 if ! is_free_coord ($mapid,       $x, ($y + 1));
   return 0 if ! is_free_coord ($mapid, ($x + 1), ($y + 1));
   return 0 if ! is_free_coord ($mapid, ($x - 1), ($y + 1));

   return 1;
}

sub generate_free_coord {

   foreach my $plus (0 .. 10) {

      foreach (1 .. 100) {

         my ($x, $y, $mapid) = create_new_coord ($plus);

         next if ! is_free_district ($mapid, $x, $y);

         return ($x, $y, $mapid);
      }
      warn "generate_free_coord: 100 tries failed. Detect High Density. Go to next map\n";
   }
   warn "generate_free_coord failed! 100 map busy!!!!!\n";

   return (0, 0, 0);
}

sub unauthorised_create_castle {
   my $struct = shift;

   my $key       = $struct->{key};
   my $stepdt    = $struct->{stepdt};
   my $castle_id = $struct->{id};      # TODO check exists
   my $x         = $struct->{x};
   my $y         = $struct->{y};
   my $mapid     = $struct->{mapid};
   my $dt        = $struct->{dt};      # TODO check real <CURDATE >REAL?

   if (restrict_new_castle ($key)) {

      return (1, "No time for new castle");
   }

   if (! is_free_district ($mapid, $x, $y)) {

      return (1, "New castle $castle_id in restricted area $x $y");
   }

   my $castle_dir = catfile (get_decline_dir (), 'data', $castle_id);
   create_directory_tree ($castle_id);
   my $data = {
      key           => $key,
      dt            => $dt,
      id            => $castle_id,
      x             => $x,
      y             => $y,
      gold          => 50,
      population    => 100,
      power         => 0,
      mapid         => $mapid,
      army          => {},
      stepdt        => $stepdt,
      laststep      => $dt,
      opid          => 0,
   };
   my $op_data = dclone ($data);
   my ($json, $sha1)     = json_with_fixed_datatypes ($data);
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
   my ($x, $y, $mapid) = generate_free_coord ();
   return 0 if ! $mapid;
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
   my $dt        = $struct->{dt}; # TODO check
   my $army_id   = $struct->{army_id};
   my $army_name = $struct->{name};

   my $castle_ref = load_castle ($castle_id);
   return (1, "Invalid castle id $castle_id") unless $castle_ref->{mapid};

   return (1, "Invalid name: $army_name") if ! exists $army->{$army_name};

   return (1, "Not enought gold") if $army->{$army_name}{1}{cost} > $castle_ref->{gold};
   return (1, "Not enought population") if $castle_ref->{population} < 10;
   return (1, "Internal error: key exists") if exists $castle_ref->{army}{$army_id};

   my $clone_data = dclone ($castle_ref);
   return (1, "Serialization error: $@") if ! exists $clone_data->{mapid};
   $clone_data->{gold}       -= $army->{$army_name}{1}{cost};
   $clone_data->{population} -= 10;
   $clone_data->{power}      += $army->{$army_name}{1}{cost};

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

   ++$clone_data->{opid};

   my (undef, $old_sha1) = json_with_fixed_datatypes ($castle_ref);
   my ($json, $sha1)     = json_with_fixed_datatypes ($clone_data);

   return atomic_write_data ($castle_id, $json, {
      op      => 'unauthorised_buy_army',
      army_id => $army_id,
      name    => $army_name,
      dt      => $dt,
      new     => $sha1,
      old     => $old_sha1,
      opid    => $clone_data->{opid}
   });
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

   my $rollback = rollback_save_state ($castle_id);

   my ($rc, @data) = unauthorised_buy_army ({
      id      => $castle_id,
      dt      => $dt,
      army_id => $dt . $mcs,
      name    => $army_name
   });

   return $data[0] if $rc;
   return rollback_restore ($rollback, @data) if gpg_create_signature (@data);
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
   my @list = @_;
   my ($rc) = has_move_army (@list);
   return $rc;
}

sub unauthorised_move_army {
   my $struct = shift;

   my $castle_id = $struct->{id};
   my $army_id   = $struct->{army_id};
   my $direction = $struct->{direction};

   my ($rc, $err, undef) = has_move_army ($castle_id, $army_id, $direction);
   return (1, $err) unless $rc;
   return (1, "Unimplemented attack") if $rc == 2; # TODO

   my $castle_ref = load_castle ($castle_id);

   my $clone_data = dclone ($castle_ref);
   return (1, "Internal error: $@") if ! exists $clone_data->{mapid};
   $clone_data->{army}{$army_id}{movement}--;

   ($clone_data->{army}{$army_id}{x}, $clone_data->{army}{$army_id}{y}) =
      coord_for_direction ($clone_data->{army}{$army_id}{x}, $clone_data->{army}{$army_id}{y}, $direction);

   ++$clone_data->{opid};

   my (undef, $old_sha1) = json_with_fixed_datatypes ($castle_ref);
   my ($json, $sha1)     = json_with_fixed_datatypes ($clone_data);
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

   my $rollback = rollback_save_state ($castle_id);

   my ($rc, @data) = unauthorised_move_army ({
      id        => $castle_id,
      dt        => get_utc_time (),
      army_id   => $aid,
      direction => $direction
   });

   return $data[0] if $rc;
   return rollback_restore ($rollback, @data) if gpg_create_signature (@data);
   return 0;
}

sub unauthorised_increase_population {
   my $struct = shift;

   my $castle_ref = load_castle ($struct->{id});
   my $clone_data = dclone ($castle_ref);
   $clone_data->{laststep}            = $struct->{dt};
   $clone_data->{gold_increase}       = $struct->{gold_increase};
   $clone_data->{population_increase} = $struct->{population_increase};
   $clone_data->{army_tarif}          = $struct->{army_tarif};

   $clone_data->{gold}       += $struct->{gold_increase};
   $clone_data->{gold}       -= $struct->{army_tarif};
   $clone_data->{population} += $struct->{population_increase};

   ++$clone_data->{opid};

   my (undef, $old_sha1) = json_with_fixed_datatypes ($castle_ref);
   my ($json, $sha1)     = json_with_fixed_datatypes ($clone_data);
   my $op = {
      op                  => 'unauthorised_increase_population',
      gold_increase       => $struct->{gold_increase},
      population_increase => $struct->{population_increase},
      army_tarif          => $struct->{army_tarif},
      dt                  => $struct->{dt},
      new                 => $sha1,
      old                 => $old_sha1,
      opid                => $clone_data->{opid},
   };
   return atomic_write_data ($struct->{id}, $json, $op);
}

sub unauthorised_demobilization {
   my $struct = shift;

   my $castle_ref = load_castle ($struct->{id});
   my $clone_data = dclone ($castle_ref);

   my $name  = $castle_ref->{army}{$struct->{aid}}{name};

   return (1, "Invalid army $name in castle " . $castle_ref->{id})
      if ! $name || ! exists $army->{$name};

   $clone_data->{gold}  += $army->{$name}{1}{cost};
   $clone_data->{power} -= $army->{$name}{1}{cost};

   delete ($clone_data->{army}{$struct->{aid}});

   ++$clone_data->{opid};

   my (undef, $old_sha1) = json_with_fixed_datatypes ($castle_ref);
   my ($json, $sha1)     = json_with_fixed_datatypes ($clone_data);
   my $op = {
      op   => 'unauthorised_demobilization',
      dt   => $struct->{dt},
      aid  => $struct->{aid},
      new  => $sha1,
      old  => $old_sha1,
      opid => $clone_data->{opid},
   };
   return atomic_write_data ($struct->{id}, $json, $op);
}

sub demobilization {
   my ($castle, $aid) = @_;

   my $castle_ref = load_castle ($castle);

   return "demobilization: Unable load castle $castle" if ref ($castle_ref) ne 'HASH';

   return "demobilization: ArmyId $aid not found in Castle" if ! exists $castle_ref->{army}{$aid};

   my $rollback = rollback_save_state ($castle);
   my ($rc, @data) = unauthorised_demobilization ({
      id  => $castle,
      dt  => get_utc_time (),
      aid => $aid
   });
   warn $data[0] . "\n" if $rc;
   if (! $rc && gpg_create_signature (@data)) {

      return rollback_restore ($rollback, @data);
   }
}

# население плюс 2 процента каждые три часа
# деньги 4 процента от населения
sub increase_population {
   my ($castle_ref, $dt) = @_;

   my $population = $castle_ref->{population};
   my $gold       = ($population / 3) / 8;

   $population = int ($population / 50);
   $population = 1 unless $population;

   my $army_tarif = 0;
   foreach my $arm_id (keys %{$castle_ref->{army}}) {

      my $name  = $castle_ref->{army}{$arm_id}{name};

      if (! exists $army->{$name}{1}{tarif}) {

         return "Invalid army $name in castle " . $castle_ref->{id}; 
      }
      $army_tarif += $army->{$name}{1}{tarif};
   }

   my $rollback = rollback_save_state ($castle_ref->{id});
   my ($rc, @data) = unauthorised_increase_population ({
      id                  => $castle_ref->{id},
      dt                  => $dt,
      gold_increase       => $gold,
      population_increase => $population,
      army_tarif          => $army_tarif
   });
   warn $data[0] . "\n" if $rc;
   if (! $rc && gpg_create_signature (@data)) {

      return rollback_restore ($rollback, @data);
   }
}

sub increase_movement {
   my ($castle_ref, $dt) = @_;

   my $clone_data = dclone ($castle_ref);

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
   ++$clone_data->{opid};

   my (undef, $old_sha1) = json_with_fixed_datatypes ($castle_ref);
   my ($json, $sha1)     = json_with_fixed_datatypes ($clone_data);

   my $rollback = rollback_save_state ($castle_ref->{id});
   my ($rc, @data) = atomic_write_data ($castle_ref->{id}, $json, {
      op   => 'unauthorised_increase_movement',
      data => $ops,
      dt   => $dt,
      new  => $sha1,
      old  => $old_sha1,
      opid => $clone_data->{opid}
   });

   return $data[0] if $rc;
   if (my $err = gpg_create_signature (@data)) {

      return join (' ', $err, rollback_restore ($rollback, @data));
   }
}

sub increase_keepalive {
   my ($castle_ref, $dt) = @_;

   # TODO keepalive
   return 0;
}

sub local_update_castle {
   my $castlehr = shift;

   my $dt = get_utc_time ();
   return 0 if $castlehr->{laststep} > ($dt - (30*60));

   my $basedt = ($castlehr->{laststep} > $castlehr->{dt} ? $castlehr->{laststep} : $castlehr->{dt});

   return "Error laststep > current date" if $basedt > $dt;

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

            if (my $err = increase_movement ($castlehr, $basedt)) {

               return "increase_movement : $err";
            }
            $castlehr = load_castle ($castlehr->{id});
         }
         if (! ($datetime->hour_1() % 3)) {

            if (my $err = increase_population ($castlehr, $basedt)) {

               return "increase_population : $err";
            }
            $castlehr = load_castle ($castlehr->{id});
         }
         $basedt += (30*60);
      }
      else {

         $basedt += 60;
      }
   }
   return '';
}

sub local_updates {

   my $dt = get_utc_time ();
   my $key = get_key_id ();
   foreach my $castlehr (list_my_castles ($key)) {

      if (my $err = local_update_castle ($castlehr)) {

         return $err;
      }
      return '' if $dt < (get_utc_time () - 2);
   }
   return '';
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
   my ($type, $castle_id, $point_template, $needed_sha1, $key) = @_;

   my $ua = LWP::UserAgent->new;
   $ua->timeout (20);

   my ($subdir, $file) = parse_op_id (0);

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
   my $sig_file  = catfile (get_decline_dir (), 'tmp', "$file.sig");
   my $res1 = $ua->mirror ("$url/$castle_id/$subdir/$file.json", $json_file);
   my $res2 = $ua->mirror ("$url/$castle_id/$subdir/$file.sig",  $sig_file);

   if ($res1->code !~ /^(2|3)/ || $res2->code !~ /^(2|3)/) {

      my $real_sha1 = sha1_file_hex (castle_state_file ($castle_id));
      if ($real_sha1 ne $needed_sha1) {

         warn "Not found next file $file (but kingdom incomplete) $real_sha1 $needed_sha1\n";
      }
      return 0;
   }

   if (my $rc = gpg_verify_signature ($key, $json_file, $sig_file)) {

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

   my $real_sha1 = sha1_file_hex (castle_state_file ($castle_id));

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
      my $key = key_for_point ($p);
      next if $p eq get_my_address ();
      next if ($points->{$p}{livedt} || 0) < get_utc_time () - 20;
      next if ! $url;
      next if ! $key;

      my $response = $ua->mirror ("$url/kingdom.json", catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json"));

      if ($response->code !~ /^(2|3)/) {

         warn "Debug: $url/kingdom.json : " . $response->code . "\n";
         next;
      }

      next if ( Decline::sha1_file_hex (kingdom_json_file ()) eq
                Decline::sha1_file_hex (catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json")));

      my $old_struct = Decline::load_json (kingdom_json_file ());
      my $new_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'remote', "$p.kingdom.json"));

      die "Bad keys.json\n" if ref ($new_struct) ne 'HASH';

      # TODO sort by date
      foreach my $k (keys %{$new_struct}) {

         # sha1 in kingdom.json == state.json: kingdom.json incomplete another side
         next if $new_struct->{$k} eq sha1_file_hex (castle_state_file ($k));

         if (my $dt = Decline::sync_castle ((exists $old_struct->{$k} ? "update" : "create"), $k, $p, $new_struct->{$k}, $key)) {

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
   my $count = 0;

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

      next if (Decline::sha1_file_hex (catfile (get_decline_dir (), 'data', 'remote', "$p.keys.json")) eq
               Decline::sha1_file_hex (catfile (get_decline_dir (), 'data', 'keys.json')));

      warn "$p exchange keys.json\n";

      my $old_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'keys.json'));
      my $new_struct = Decline::load_json (catfile (get_decline_dir (), 'data', 'remote', "$p.keys.json"));

      if (ref ($new_struct) ne 'HASH') {

         warn "Bad downloaded data/remote/$p.keys.json\n";
         next;
      }

      foreach my $k (keys %{$new_struct}) {

         next if exists $old_struct->{$k};

         warn "New key $k\n";
         my $tmp_file = catfile (get_decline_dir (), 'tmp', "$k.asc");
         $response = $ua->mirror ($url . "/$k.asc", $tmp_file);
         if ($response->code =~ /^(2|3)/) {

            my ($rc, $err) = gen_address ($new_struct->{$k}{address});
            if (! $rc) {

               warn "Bad address in $tmp_file : $err. add_key() skipped\n";
               next;
            }

            if (! add_key ($tmp_file, $k)) {

               warn "add_key() failed (bad file $tmp_file)\n";
               next;
            }
            init_keys_json ();
            set_key_attribute ($k, 'address', $new_struct->{$k}{address});
            set_point_attribute ($new_struct->{$k}{address}, 'self', 0);
            $count++;
         }
         unlink ($tmp_file);
      }
   }
   return $count++;
}

sub prepare_points {

   my $points = get_points ();
   my $i = 0;
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
      if ($r->res->code && $r->res->code == 200) {

         warn "$url IS LIVE\n";
         Decline::set_point_attribute ($p, 'livedt', Decline::get_utc_time ());
         $i++;
      }
   }
   return $i;
}

sub remote_updates {
   prepare_points ();
   sync_keys ();
   my $dt = sync_castles ();
   return $dt;
}

sub get_updates {

   if (my $err = local_updates ()) {

      return $err;
   }
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

   my %seen   = ();
   my $result = [];

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

sub rating {
   my $mapid = shift;

   my $result = {};

   my @cache = grep { $_->{mapid} == $mapid } list_castles ();

   $result->{gold}  = [ ((sort {$a->{gold}  <=> $a->{gold} } @cache)[0 .. 19]) ];

   $result->{power} = [ ((sort {$a->{power} <=> $a->{power}} @cache)[0 .. 19]) ];

   return $result;
}

1;
