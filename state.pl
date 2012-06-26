
# perl state.pl cached-descriptors
# perl state.pl cached-descriptors 128.31.0.34
# perl state.pl cached-descriptors 128.31.0.34:9101
# perl state.pl cached-descriptors 128.31.0.34:9101 76.73.17.194
# perl state.pl cached-descriptors 128.31.0.34:9101 76.73.17.194:9090

use strict;
use warnings;
use POSIX qw(mktime strftime);

my $timezone=28800;

if(1>scalar(@ARGV))
 {warn('Usage: state.pl cached-descriptors');
  exit();
 }
else
 {
  if(!open(FILE,$ARGV[0]))
   {warn('Can NOT open file: '.$ARGV[0]);
   }
  else
   {
    my %ip;
    for($_=1;$_<scalar(@ARGV);$_++)
     {
      if($ARGV[$_] !~ /^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})(:([0-9]{1,5})){0,1}$/)
       {
        warn('Unknown IP: '.$ARGV[$_]);
        exit();
       }
      else
       {if(defined($6))
         {$ip{$1.'.'.$2.'.'.$3.'.'.$4.':'.$6}=0;
         }
        else
         {$ip{$1.'.'.$2.'.'.$3.'.'.$4}=0;
         }
       }
     }
    while(<FILE>)
     {
      if($_ =~ /^router /)
       {
        if($_ !~ /^router ([^ ]{1,}) ([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3}) ([0-9]{1,}) [0-9]{1,} [0-9]{1,}$/)
         {warn('Unknown router: ');
          exit();
         }
        else
         {
          if(0 == $6)
           {warn('0==ORPort');
            exit();
           }
          else
           {
            my $ORPort=$2.'.'.$3.'.'.$4.'.'.$5.':'.$6;
            if(0==scalar(keys(%ip)) || exists($ip{$2.'.'.$3.'.'.$4.'.'.$5}) || exists($ip{$2.'.'.$3.'.'.$4.'.'.$5.':'.$6}))
             {my $nickname=$1;
              $_ = <FILE>;
              if($_ !~ /^platform Tor ([0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}).*on .*$/)
               {warn('Unknown platform: '.$_);
                exit();
               }
              else
               {my $torVer=$1;
                $_ = <FILE>;
                $_ = <FILE>;
                if($_ !~ /^published ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
                 {warn('Unknown published: ');
                  exit();
                 }
                else
                 {my $published=POSIX::mktime($6,$5,$4,$3,$2-1,$1-1900,0,0,-1);
                  $published+=$timezone;
                  $published=POSIX::strftime('%Y-%m-%d %H:%M:%S',gmtime( $published ));
                  $_ = <FILE>;
                  if($_ !~ /^opt fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})$/)
                   {warn('Unknown fingerprint: ');
                    exit();
                   }
                  else
                   {my $fingerprint=$1.$2.$3.$4.$5.$6.$7.$8.$9.$10;
                    print('EntryGuard '.$nickname.' '.$fingerprint.' # '.$ORPort."\n".'EntryGuardAddedBy '.$fingerprint.' '.$torVer.' '.$published."\n");
                   }
                 }
               }
             }
           }
         }
       }
     }
    close(FILE);
   }
 }
