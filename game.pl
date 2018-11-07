
BEGIN {
   use File::Basename qw(dirname basename);
   use Cwd;
   if (chdir dirname ($0)) {

      $ENV{'MOJO_HOME'} = cwd;
      $0 = basename ($0);
   }
   push @INC, 'lib';
}

use strict;
use utf8;
use warnings 'all';

use Mojo::JSON qw(decode_json encode_json);
use Mojolicious::Lite;
use File::Spec::Functions qw(catfile);
use Decline;

$Decline::decline_dir = cwd;

my $static_path = catfile ($Decline::decline_dir, 'static');

app->static->paths->[0] = $static_path;

my $hash = {
      'castle'        => {id => 1, in_castle => 1, ru => "В замок"},
      'map'           => {id => 2, in_castle => 1, ru => "Карта мира"},
      'army'          => {id => 3, in_castle => 1, ru => "Наём войска"},
      'demolish'      => {id => 4, in_castle => 1, ru => "Демобилизация"},
      'diplomacy'     => {id => 5, in_castle => 1, ru => "Мирные соглашения"},
      'clan'          => {id => 6, in_castle => 1, ru => "Клан"},
      'setting'       => {id => 7, in_castle => 1, ru => "Настройки замка"},
      'tax'           => {id => 8, in_castle => 1, ru => "Оброк"},
      'messages'      => {id => 9, in_castle => 1, ru => "Сообщения"},
      'select_castle' => {id => 1, in_castle => 0, ru => "Выбор замка"},
      'kingdom'       => {id => 2, in_castle => 0, ru => "Глобальная карта"},
      'settings'      => {id => 3, in_castle => 0, ru => "Настройки игрока"},
      'rating'        => {id => 4, in_castle => 0, ru => "Рейтинги"},
      'sync'          => {id => 5, in_castle => 0, ru => "Синхронизация"},
};

any '/:select/:castle/dynamic.js' => sub {
   my $c = shift;
   $c->stash (select => $c->param ('select'));
   
   return $c->render (template => 'dynamic_js');
};

any '/static/#file' => sub {
   my $c = shift;
   return $c->reply->static ($c->param ('file'));
};

any '/buy/:name/:castle' => sub {
   my $c   = shift;

   if (! Decline::is_my_castle (Decline::get_key_id (), $c->param ('castle'))) {

      return $c->render (text => "Unauthorised");
   }

   if (my $err = Decline::buy_army ($c->param ('castle'), $c->param ('name'))) {

      return $c->render (text => "Buy error: $err");
   }
   $c->redirect_to ("/public/army/" . $c->param ('castle'));
};

any '/create/castle/:hour' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      my $castle = Decline::create_new_castle ($key, $c->param ('hour'));
      return $c->render (text => "Unable create new castle") unless $castle;
      return $c->redirect_to ("/public/castle/$castle");
   }
   $c->render (text => "Unauthorised");
};

any '/public/:select/:castle' => sub {
   my $c   = shift;

   my $key    = Decline::get_key_id ();
   my $castle = $c->param ('castle');
   my $select = $c->param ('select');

   if (! Decline::is_my_castle ($key, $castle)) {

      return $c->render (text => "Unauthorised");
   }
   elsif (! exists $hash->{$select} || ! $hash->{$select}{in_castle}) {

      return $c->render (text => "Unknown url /$select/");
   }

   $c->stash (key      => $key);
   $c->stash (castle   => Decline::load_castle ($castle));
   $c->stash (select   => $select);
   $c->stash (hash     => $hash);
   $c->stash (army     => $Decline::army);
   $c->stash (aid      => $c->param ('aid'));
   if ($select eq 'map' && $c->param ('d')) {

      if (my $err = Decline::move_army ($castle, $c->param ('aid'), $c->param ('d'))) {

         return $c->render (text => "Move error $err");
      }
      return $c->redirect_to ("/public/map/$castle/?aid=" . $c->param ('aid'));
   }

   $c->render (template => $select);
};

any '/public/update' => sub {
   my $c   = shift;

   if (Decline::lock_data ("update")) {

      if (my $dt = Decline::get_updates ()) {

         Decline::unlock_data ("update");
         $dt = scalar (localtime ($dt)) if $dt =~ /^\d+$/;
         return $c->render (text => $dt);
      }
      Decline::unlock_data ("update");
   }
   $c->render (text => '');
};

any '/svg/kingdom/:mapid/#name' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      $c->stash (svg => Decline::generate_svg ($c->param ('mapid'), $key));
      return $c->render (template => 'kingdom_svg', format => 'svg');
   }
   $c->render (text => 'Unautorized');
};

any '/global/:select' => sub {
   my $c = shift;
   my $select = $c->param ('select');
   my $key = Decline::get_key_id ();
   my $params = {};
   my $address = Decline::get_my_address ();

   if ($select ne 'sync') {

      if (! $key || ! $address) {

         return $c->redirect_to ("/global/sync");
      }
   }

   if (! $key) {

      if ($c->param ('yes')) {

         Decline::create_new_key ();
         $key = Decline::get_key_id ();
         return $c->redirect_to ("/global/sync");
      }
      else {

         $params->{yes} = $c->param ('yes');
      }
   }

   if ($select eq 'select_castle') {

      $params->{hour}     = $c->param ('hour');
      $params->{restrict} = Decline::restrict_new_castle ($key);
      $params->{list}     = [ Decline::list_my_castles ($key) ];
      (undef, undef, $params->{next_map_id}) = Decline::generate_free_coord ();
   }
   elsif ($select eq 'settings') {

      $params->{files} = Decline::update_program_files (0,$c->param ('update'));
   }
   elsif ($select eq 'sync') {

      if ($c->param ('ip') && $c->param ('port')) {

         my $template = join (':', 'http', $c->param ('ip'), $c->param ('port'));
         my ($valid) = Decline::gen_address ($template);
         if ($valid) {

            Decline::set_point_attribute ($template, 'self', ($c->param ('self') ? 1 : 0));
            return $c->redirect_to ("/global/sync");
         }
         return $c->render (text => "Invalid IP-address or PORT");
      }

      $params->{keys}    = Decline::get_keys ();
      $params->{points}  = Decline::get_points ();
      $params->{address} = $address;
   }
   elsif ($select eq 'rating') {

      $params->{mapid}      = ($c->param ('map') || 1);
      $params->{rating}     = Decline::rating ($params->{mapid});
      $params->{max_map_id} = Decline::get_max_map_id ();
   }
   elsif ($select eq 'kingdom') {

      $params->{mapid}      = ($c->param ('map') || 1);
      $params->{max_map_id} = Decline::get_max_map_id ();
   }

   $c->stash (hash => $hash, castle => undef, select => $select, key => $key, params => $params);

   if (exists $hash->{$select} && ! $hash->{$select}{in_castle}) {

      return $c->render (template => $select);
   }
   $c->render (text => "Unknown url /$select/");
};

any '' => sub {
   my $c   = shift;

   my $key = Decline::get_key_id ();
   unless ($key) {

      return $c->redirect_to ("/global/sync");
   }
   return $c->redirect_to ("/global/select_castle");
};

app->start ('daemon', '-l', 'http://*:3000');
