
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
use Mojo::JSON qw(decode_json encode_json);
use Mojolicious::Lite;
use File::Spec::Functions qw(catfile);
use Decline;
use utf8;

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
   $c->stash (select => $c->param('select'));
   
   return $c->render (template => 'dynamic_js');
};

any '/static/#file' => sub {
   my $c = shift;
   return $c->reply->static ($c->param ('file'));
};

any '/buy/:name/:castle' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      if (my $err = Decline::buy_army ($c->param('castle'), $c->param('name'))) {

         return $c->render (text => "Buy error: $err");
      }
      return $c->redirect_to ("/public/army/" . $c->param('castle'));
   }
   $c->render (text => "Unauthorised");
};

any '/public/:select/:castle' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      my $select = $c->param ('select');
      my $castle = $c->param ('castle');
      my $hour   = $c->param ('hour');
      if ($castle eq 'new') {
         my $castle_id = Decline::create_new_castle ($key, $hour);
         return $c->render (text => "Unable create new castle") unless $castle_id;
         return $c->redirect_to ("/public/castle/$castle_id");
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
         return $c->redirect_to ("/public/map/$castle/?aid=" . $c->param('aid'));
      }
      if (exists $hash->{$select} && $hash->{$select}{in_castle}){

         return $c->render (template => $select);
      } else {

         return $c->render (text => "Unknown url /$select/");
      }
   }
   $c->render (text => "Unauthorised");
};

any '/public/update' => sub {
   my $c   = shift;
   if (Decline::get_updates ()) {
      return $c->render (text => scalar (localtime));
   }
   $c->render (text => '');
};

any '/svg/kingdom/#name' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      $c->stash (svg => Decline::generate_svg ($c->param('name'), $key));
      return $c->render (template => 'kingdom_svg', format => 'svg');
   }
   $c->render (text => 'Unautorized');
};

any '/global/:select' => sub {
   my $c = shift;
   my $select = $c->param('select');
   my $key = Decline::get_key_id ();
   my $params = {};
   if (! $key && $select ne 'sync') {

      return $c->render (text => "Unautorized");
   }
   if (! $key) {

      if ($c->param('gpg_path') && -e $c->param('gpg_path')) {
         $params->{gpg_path} = $c->param('gpg_path');
      }
      else {
         $params->{gpg_path} = Decline::get_gpg_path ();
      }

      if ($c->param('yes')) {

         Decline::create_new_key ($params->{gpg_path});
         $key = Decline::get_key_id ();
         Decline::set_gpg_path ($params->{gpg_path}) if $key;
      }
      else {

         $params->{yes} = $c->param('yes');
      }
   }

   if ($select eq 'select_castle') {

      $params->{hour}     = $c->param ('hour');
      $params->{restrict} = Decline::restrict_new_castle ($key);
      $params->{list}     = [ Decline::list_my_castles ($key) ];
   }
   elsif ($select eq 'settings') {

      $params->{files} = Decline::update_program_files ();
   }
   elsif ($select eq 'sync') {

      if ($c->param ('ip') && $c->param ('ip') =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/ && $c->param ('port') && $c->param ('port') =~ /^(\d+)$/) {

         Decline::set_key_attribute ($key, 'ip', $c->param ('ip'));
         Decline::set_key_attribute ($key, 'port', $c->param ('port'));
         return $c->redirect_to ("/global/sync");
      }
      $params->{keys} = Decline::get_keys ();
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
