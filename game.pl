
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
      'castle'    => {id => 1, ru => "В замок"},
      'map'       => {id => 2, ru => "Карта мира"},
      'army'      => {id => 3, ru => "Наём войска"},
      'demolish'  => {id => 4, ru => "Демобилизация"},
      'diplomacy' => {id => 5, ru => "Мирные соглашения"},
      'clan'      => {id => 6, ru => "Клан"},
      'setting'   => {id => 7, ru => "Настройки замка"},
      'tax'       => {id => 8, ru => "Оброк"},
      'messages'  => {id => 9, ru => "Сообщения"},
};

any '/:select/:castle/dynamic.js' => sub {
   my $c = shift;
   $c->stash (select => $c->param('select'));
   
   return $c->render (template => 'dynamic_js');
};

any '/static/:file' => sub {
   my $c = shift;
   my $file = $c->param('file');

   foreach my $valid_extention ('jpg', 'css', 'js', 'gif', 'png') {
      if (-f catfile ($static_path, "$file.$valid_extention")){
         return $c->reply->static( "$file.$valid_extention" );
      }
   }      
   $c->render (text => "Error $file");
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
      if (exists $hash->{$select}){

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

any '/public/kingdom' => sub {
   my $c   = shift;
   $c->stash (castle => undef, hash => undef, select => 'kingdom');
   $c->render (template => 'kingdom');
};

any '/svg/kingdom/#name' => sub {
   my $c   = shift;

   if (my $key = Decline::get_key_id ()) {

      $c->stash (svg => Decline::generate_svg ($c->param('name'), $key));
      return $c->render (template => 'kingdom_svg', format => 'svg');
   }
   $c->render (text => 'Unautorized');
};


any '' => sub {
   my $c   = shift;

   my $key = Decline::get_key_id ();

   unless ($key) {
      $key = Decline::create_new_key ();
   }

   my @list = Decline::list_my_castles ($key);

   $c->stash (hour      => $c->param ('hour'));
   $c->stash (restrict  => Decline::restrict_new_castle ($key));
   $c->stash (key       => $key);
   $c->stash (list      => \@list);
   $c->stash (castle    => undef, hash => undef, select => undef, army => {});
   $c->render (template => 'content');
};

app->start ('daemon', '-l', 'http://*:3000');
