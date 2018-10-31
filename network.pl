
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

my $static_path = catfile ($Decline::decline_dir, 'data');

app->static->paths->[0] = $static_path;

any '/data/#file' => sub {
   my $c = shift;
   return $c->reply->static ($c->param ('file'));
};

any '/data/:castle/#file' => sub {
   my $c = shift;
   return $c->reply->static (catfile ($c->param ('castle'), $c->param ('file')));
};


any '' => sub {
   my $c = shift;
   $c->render (text => 'Its Work');
};

if (my $port = Decline::get_my_port ()) {

   app->start ('daemon', '-l', "http://*:$port");
}
else {

   die "Set PORT in game web-interface\n";
}
