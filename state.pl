
# perl state.pl cached-descriptors
# perl state.pl cached-descriptors 128.31.0.34
# perl state.pl cached-descriptors 128.31.0.34:9101
# perl state.pl cached-descriptors 128.31.0.34:9101 76.73.17.194
# perl state.pl cached-descriptors 128.31.0.34:9101 76.73.17.194:9090

# perl state.pl cached-descriptors cached-descriptors.new 128.31.0.34 76.73.17.194
# perl state.pl cached-descriptors 128.31.0.34 cached-descriptors.new  76.73.17.194
# perl state.pl 128.31.0.34 cached-descriptors 76.73.17.194 cached-descriptors.new
# perl state.pl 128.31.0.34 76.73.17.194 cached-descriptors cached-descriptors.new

# perl state.pl old cached-descriptors

# echo grep -B4 $(sed -ne 's/^EntryGuard [^ ]* \([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)\([0-9A-F]\{4\}\)$/-e "^opt fingerprint \1 \2 \3 \4 \5 \6 \7 \8 \9" /p' state | tr -d '\n') cached-descriptors cached-descriptors.new | sh | sed -ne 's/^cached-descriptors\([.]new\)\{0,1\}-router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/nc -w 1 \2.\3.\4.\5 \6 -e cat/p'
# sed -ne 's/^router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/\1.\2.\3.\4 \5/p' cached-descriptors cached-descriptors.new | sort | uniq | while read LINE ; do echo -n | nc -w 1 ${LINE} 2> /dev/null ; if [ 0 -eq $? ] ; then echo ${LINE} ; fi ; done

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
  my $old=0;
  my $i=0;
  my @files;
  my %ip;
  for($_=0;$_<scalar(@ARGV);$_++)
   {
    if($ARGV[$_] eq 'old')
     {$old=1;
     }
    elsif($ARGV[$_] !~ /^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})(:([0-9]{1,5})){0,1}$/)
     {if(!open($files[$i],'<',$ARGV[$_]))
       {warn('Can NOT open file: '.$ARGV[$_]);
        exit();
       }
      else
       {$i++;
       }
     }
    else
     {if(!defined($6))
       {$ip{$1.'.'.$2.'.'.$3.'.'.$4}=0;
       }
      else
       {if(0==$6)
         {warn('0==Port');
          exit();
         }
        else
         {$ip{$1.'.'.$2.'.'.$3.'.'.$4.':'.$6}=0;
         }
       }
     }
   }
  if(1>scalar(@files))
   {warn('NO file defined!');
    exit();
   }
  else
   {
    for($i=0;$i<scalar(@files);$i++)
     {
      while(readline($files[$i]))
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
                $_=readline($files[$i]);
                if($_ !~ /^platform Tor ([0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}).*on .*$/)
                 {warn('Unknown platform: '.$_);
                  exit();
                 }
                else
                 {my $torVer=$1;
                  readline($files[$i]);
                  $_=readline($files[$i]);
                  if($_ !~ /^published ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
                   {warn('Unknown published: '.$_);
                    exit();
                   }
                  else
                   {my $published=POSIX::strftime('%Y-%m-%d %H:%M:%S',gmtime(POSIX::mktime($6,$5,$4,$3,$2-1,$1-1900,0,0,-1)+$timezone));
                    if($1.'-'.$2.'-'.$3.' '.$4.':'.$5.':'.$6 ne $published)
                     {warn('Unknown published time: '.$_);
                      exit();
                     }
                    else
                     {if(0==$old)
                       {$published=POSIX::strftime('%Y-%m-%d %H:%M:%S',gmtime());
                       }
                      $_=readline($files[$i]);
                      if($_ !~ /^opt fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})$/)
                       {warn('Unknown fingerprint: '.$_);
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
       }
      close($files[$i]);
     }
   }
 }
