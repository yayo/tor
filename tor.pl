
# perl tor.pl s cached-descriptors 128.31.0.34
# cat cached-descriptors | perl tor.pl s - 128.31.0.34
# perl tor.pl s cached-descriptors 128.31.0.34:9101
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194:9090
# perl tor.pl s cached-descriptors cached-descriptors.new 128.31.0.34 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34 cached-descriptors.new  76.73.17.194
# perl tor.pl s 128.31.0.34 cached-descriptors 76.73.17.194 cached-descriptors.new
# perl tor.pl s 128.31.0.34 76.73.17.194 cached-descriptors cached-descriptors.new

# perl tor.pl S cached-descriptors 128.31.0.34

# perl tor.pl t cached-descriptors cached-descriptors.new | 7za a -mx9 -si cached-descriptors.7z
# Verify:
# sed -ne 's/^router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/\1.\2.\3.\4 \5/p' cached-descriptors cached-descriptors.new | sort | uniq | wc
# 7za x -so cached-descriptors.7z | perl tor.pl i - | wc

# perl tor.pl e state cached-descriptors cached-descriptors.new
# perl tor.pl i cached-descriptors cached-descriptors.new | sed -e 's/:/ /g' | while read LINE ; do echo -n | nc -w 1 ${LINE} 2> /dev/null ; if [ 0 -eq $? ] ; then echo ${LINE} ; fi ; done

use strict;
use warnings;
use POSIX qw(mktime strftime);
use File::Basename;

my $timezone=28800;

my %ips;
my %fingerprints;
my %entrys;

sub parse($)
 {
  if($_[0] !~ /^\@downloaded-at [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\n\@source "[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}"\nrouter ([0-9A-Za-z]{1,19}) ([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3}) ([0-9]{1,}) [0-9]{1,} [0-9]{1,}\nplatform Tor ([0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,})(?:-alpha|-beta|-rc|-alpha-dev|-beta-dev|-rc-dev|-dev){0,1} (?:\(git-[0-9a-f]{16}\) ){0,1}on (?:Windows|Linux|FreeBSD|OpenBSD|NetBSD|SunOS|Darwin|DragonFly|Very recent version of Windows)[^\n]{0,}\nopt protocols Link 1 2 Circuit 1\npublished ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\nopt fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})\nuptime [0-9]{1,9}\nbandwidth [0-9]{1,10} [0-9]{1,10} [0-9]{1,10}\n(?:opt extra-info-digest [0-9A-F]{40}\n){0,1}(?:opt caches-extra-info\n){0,1}onion-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\n(?:family(?: \$[0-9A-Fa-f]{40}){0,}(?: [^ \n]{1,}){0,}\n){0,1}(?:opt hibernating 1\n){0,1}(?:opt hidden-service-dir\n){0,1}(?:opt allow-single-hop-exits\n){0,1}(?:contact [^\n]{1,}\n){0,1}(?:(?:reject|accept) (?:\*|[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(?:\/[0-9]{1,2}){0,1}:(?:\*|[0-9]{1,5}(?:-[0-9]{1,5}){0,1})\n){1,}router-signature\n-----BEGIN SIGNATURE-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{43}=\n-----END SIGNATURE-----\n$/)
   {warn('UnKnown router:'."\n".$_[0]);
    exit();
   }
  else
   {
    my $published=POSIX::mktime($13,$12,$11,$10,$9-1,$8-1900,0,0,-1)+$timezone;
    my $t2=POSIX::strftime('%Y-%m-%dT%H:%M:%SZ',gmtime($published));
    if($8.'-'.$9.'-'.$10.'T'.$11.':'.$12.':'.$13.'Z' ne $t2)
     {warn('UnKnown published time: '.$_[0]);
      exit();
     }
    else
     {if(0==$6)
       {warn('0==ORPort');
        exit();
       }
      else
       {my $ORPort=$2.'.'.$3.'.'.$4.'.'.$5;
        $ips{$ORPort}{$6}=0;
        $ORPort.=':'.$6;
        if(!exists($_{$ORPort})||(exists($_{$ORPort})&&$_{$ORPort}[1]<$published))
         {
          my $fingerprint=$14.$15.$16.$17.$18.$19.$20.$21.$22.$23;
          $fingerprints{$fingerprint}{$ORPort}=0;
          @_=($_[0],$published,$fingerprint,$1,$7);
          $_{$ORPort}=\@_;
         }
       }
     }
   }
 }

if(1>scalar(@ARGV))
 {warn('Usage: tor.pl cached-descriptors');
  exit();
 }
else
 {my $cmd;
  my %ip;
  for($_=0;$_<scalar(@ARGV);$_++)
   {
    if('i' eq $ARGV[$_])
     {$cmd='i'; # list IPs in cached-descriptors
     }
    elsif('s' eq $ARGV[$_] || 'S' eq $ARGV[$_])
     {$cmd=$ARGV[$_]; # build state from IPs
     }
    elsif('t' eq $ARGV[$_])
     {$cmd='t'; # remove duplicated IPs in cached-descriptors
     }
    elsif('e' eq $ARGV[$_])
     {$cmd='e'; # list IPs in state
     }
    elsif($ARGV[$_] =~ /^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})(:([0-9]{1,5})){0,1}$/)
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
    else
     {if('state' eq basename($ARGV[$_]))
       {if(!open(FILE,'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {my $entry0=scalar(keys(%entrys));
          while(my $line=<FILE>)
           {if($line =~ /^EntryGuard [0-9A-Za-z]{1,19} ([0-9A-F]{40})(?:[ ]|#[^\n]{0,}){0,}\n$/)
             {$entrys{$1}=0;
             }
           }
          close(FILE);
          if(scalar(keys(%entrys))<=$entry0)
           {warn('NO "EntryGuard" defined in state file: '.$ARGV[$_]);
            exit();
           }
         }
       }
      else
       {my $f;
        if(!('-' eq $ARGV[$_] && ($f=*STDIN)) && !open($f,'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {if(defined(my $r=readline($f)))
           {if($r !~ /^\@downloaded-at ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
             {warn('UnKnown LINE1: '.$r);
              exit();
             }
            else
             {while(my $line=readline($f))
               {if($line !~ /^\@downloaded-at /)
                 {$r.=$line;
                 }
                else
                 {if($line !~ /^\@downloaded-at ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
                   {warn('UnKnown @downloaded-at: '.$line);
                    exit();
                   }
                  else
                   {parse($r);
                    $r=$line;
                   }
                 }
               }
              parse($r);
             }
           }
          close($f);
         }
       }
     }
   }
  if(!defined($cmd))
   {warn('NO Command defined!');
    exit();
   }
  else
   {if(1>scalar(keys(%_)))
     {warn('NO cached-descriptors defined!');
      exit();
     }
    else
     {foreach(keys(%ip))
       {if(exists($_{$_})){}
        elsif(exists($ips{$_}))
         {foreach my $port (keys(%{$ips{$_}}))
           {$ip{$_.':'.$port}=0;
           }
          delete($ip{$_});
         }
        else
         {warn('Not Found: '.$_);
          exit;
         }
       }
      undef(%ips);
      if('i' eq $cmd)
       {foreach(keys(%_))
         {print($_."\n");
         }
       }
      elsif('s' eq $cmd || 'S' eq $cmd)
       {if(0==scalar(keys(%ip)))
         {warn('NO IP defined!');
          exit();
         }
        else
         {foreach(keys(%ip))
           {print('EntryGuard '.$_{$_}[3].' '.$_{$_}[2].' # '.$_."\n".'EntryGuardAddedBy '.$_{$_}[2].' '.$_{$_}[4].' '.POSIX::strftime('%Y-%m-%d %H:%M:%S',('S' eq $cmd ? gmtime($_{$_}[1]):gmtime()))."\n");
           }
         }
       }
      elsif('t' eq $cmd)
       {$_= 0==scalar(keys(%ip)) ? \%_ : \%ip ;
        foreach(sort{ $_{$a}[1] <=> $_{$b}[1] || $a cmp $b }(keys(%$_)))
         {print($_{$_}[0]);
         }
       }
      elsif('e' eq $cmd)
       {if(0==scalar(keys(%entrys)))
         {warn('state file NOT defined!');
          exit();
         }
        else
         {foreach(keys(%entrys))
           {if(!exists($fingerprints{$_}))
             {warn('Not matched fingerprints: '.$_);
              exit();
             }
            else
             {foreach(keys(%{$fingerprints{$_}}))
               {print($_."\n");
               }
             }
           }
         }
       }
      else
       {warn('NOT Implemented Command: '.$cmd);
        exit();
       }
     }
   }
 }
