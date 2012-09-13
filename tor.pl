
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

# CREATE TABLE ip(id INTEGER PRIMARY KEY AUTOINCREMENT,ip integer(4) not null ,port integer(2) not null,unique(ip,port));
# CREATE TABLE "connect"(ip INTEGER not null references ip(id),time integer(4) not null,connectivity integer(1) not null,primary key(ip,time));
# SELECT (ip.ip/16777216)||'.'||((ip.ip%16777216)/65536)||'.'||((ip.ip%65536)/256)||'.'||(ip.ip%256)||':'||port,strftime('%Y-%m-%dT%H:%M:%SZ',max(time),'unixepoch') FROM ip inner join connect on ip.id=connect.ip and time>strftime('%s')-24*60*60 and connectivity=2 GROUP BY id ORDER BY max(time) DESC LIMIT 32;

use strict;
use warnings;
use POSIX qw(mktime strftime);
use File::Basename;
use IO::Socket::INET;

my $timezone=28800;

my %ips;
my %fingerprints;
my %entrys;

sub parse($)
 {
  if($_[0] !~ /^\@downloaded-at [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\n\@source "[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}"\nrouter ([0-9A-Za-z]{1,19}) ([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3}) ([0-9]{1,5}) [0-9]{1,5} [0-9]{1,5}\n(?:or-address \[[0-9a-f:]{2,}\]:[0-9]{1,5}\n){0,1}platform Tor ([0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,})(?:-alpha|-beta|-rc|-alpha-dev|-beta-dev|-rc-dev|-dev){0,1} (?:\(git-[0-9a-f]{16}\) ){0,1}on (?:Windows|Linux|FreeBSD|OpenBSD|NetBSD|SunOS|Darwin|DragonFly|Very recent version of Windows)[^\n]{0,}\n(?:opt ){0,1}protocols Link 1 2 Circuit 1\npublished ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\n(?:opt ){0,1}fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})\nuptime [0-9]{1,9}\nbandwidth [0-9]{1,10} [0-9]{1,10} [0-9]{1,10}\n(?:(?:opt ){0,1}extra-info-digest [0-9A-F]{40}\n){0,1}(?:(?:opt ){0,1}caches-extra-info\n){0,1}onion-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\n(?:family(?: \$[0-9A-Fa-f]{40}){0,}(?: [^ \n]{1,}){0,}\n){0,1}(?:opt hibernating 1\n){0,1}(?:(?:opt ){0,1}hidden-service-dir\n){0,1}(?:(?:opt ){0,1}allow-single-hop-exits\n){0,1}(?:contact [^\n]{1,}\n){0,1}(?:(?:reject|accept) (?:\*|[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(?:\/[0-9]{1,2}){0,1}:(?:\*|[0-9]{1,5}(?:-[0-9]{1,5}){0,1})\n){1,}router-signature\n-----BEGIN SIGNATURE-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{43}=\n-----END SIGNATURE-----\n$/)
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

sub tcp($)
 {@_=split(':',$_[0],2);
  my $sock = IO::Socket::INET->new(PeerAddr=>$_[0],PeerPort=>$_[1],Proto=>'tcp',Timeout=>1);
  if(!defined($sock)||!$sock->connected)
   {return(0);
   }
  else
   {$sock->close();
    return(1);
   }
 }

sub state($$)
 {print('EntryGuard '.$_{$_[0]}[3].' '.$_{$_[0]}[2].' # '.$_[0]."\n".'EntryGuardAddedBy '.$_{$_[0]}[2].' '.$_{$_[0]}[4].' '.POSIX::strftime('%Y-%m-%d %H:%M:%S',('S' eq $_[1] ? gmtime($_{$_[0]}[1]):gmtime()))."\n");
 }

sub ip2int($)
 {@_=split(/[.:]/,$_[0],5);
  return(unpack('N',pack('C4',@_)),$_[4]);
 }

sub int2ip($$)
 {return(join('.',unpack('C4',pack('N',$_[0]))).':'.$_[1]);
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
    elsif('in' eq $ARGV[$_])
     {$cmd='in'; # list IPs count in cached-descriptors
     }
    elsif('it' eq $ARGV[$_])
     {$cmd='it'; # list IPs in cached-descriptors connected
     }
    elsif('its' eq $ARGV[$_])
     {$cmd='its'; # build state from IPs in cached-descriptors connected
     }
    elsif('itS' eq $ARGV[$_])
     {$cmd='itS'; # build state from IPs in cached-descriptors connected
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
    elsif('en' eq $ARGV[$_])
     {$cmd='en'; # list IPs count in state
     }
    elsif('et' eq $ARGV[$_])
     {$cmd='et'; # list IPs in state connected
     }
    elsif('ets' eq $ARGV[$_])
     {$cmd='ets'; # build state from IPs in state connected
     }
    elsif('etS' eq $ARGV[$_])
     {$cmd='etS'; # build state from IPs in state connected
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
           {NEXT_STATE_LINE:
            if($line =~ /^EntryGuard [0-9A-Za-z]{1,19} ([0-9A-F]{40})(?:[ ]|#[^\n]{0,}){0,}\r{0,1}\n$/)
             {$line=<FILE>;
              if($line !~ /^EntryGuardUnlistedSince [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\r{0,1}\n$/) # EntryGuardUnlistedSince should be the next line to EntryGuard OR WILL NOT be detected
               {$entrys{$1}=0;
                goto NEXT_STATE_LINE;
               }
             }
           }
          close(FILE);
          if(scalar(keys(%entrys))<=$entry0)
           {warn('NO available "EntryGuard" found in state file: '.$ARGV[$_]);
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
      if('in' eq $cmd)
       {print(scalar(keys(%_))."\n");
       }
      elsif('it' eq $cmd)
       {$|=1;
        foreach(keys(%_))
         {@_=ip2int($_);
          if(int2ip($_[0],$_[1]) ne $_)
           {warn('BAD');
            exit();
           }
          else
           {print('INSERT OR IGNORE INTO ip(ip,port) values('.$_[0].','.$_[1].');'.'INSERT INTO connect(ip,time,connectivity) values((select id from ip where ip='.$_[0],' and port=',$_[1].'),'.time().','.(tcp($_)?2:1).');'."\n");
           }
         }
       }
      elsif('i' eq $cmd || 'its' eq $cmd || 'itS' eq $cmd)
       {foreach(keys(%_))
         {if('i' eq $cmd)
           {print($_."\n");
           }
          else
           {if(tcp($_))
             {if('its' eq $cmd)
               {state($_,'s');
               }
              else
               {state($_,'S');
               }
             }
           }
         }
       }
      elsif('s' eq $cmd || 'S' eq $cmd)
       {if(0==scalar(keys(%ip)))
         {warn('NO IP defined!');
          exit();
         }
        else
         {foreach(keys(%ip))
           {state($_,$cmd);
           }
         }
       }
      elsif('t' eq $cmd)
       {$_= 0==scalar(keys(%ip)) ? \%_ : \%ip ;
        foreach(sort{ $_{$a}[1] <=> $_{$b}[1] || $a cmp $b }(keys(%$_)))
         {print($_{$_}[0]);
         }
       }
      elsif('e' eq $cmd || 'en' eq $cmd || 'et' eq $cmd || 'ets' eq $cmd || 'etS' eq $cmd)
       {if(0==scalar(keys(%entrys)))
         {warn('state file NOT defined!');
          exit();
         }
        else
         {if('en' eq $cmd)
           {print(scalar(keys(%entrys))."\n");
           }
          else
           {foreach(keys(%entrys))
             {if(!exists($fingerprints{$_}))
               {warn('Not matched fingerprints: '.$_);
                exit();
               }
              else
               {foreach(keys(%{$fingerprints{$_}}))
                 {if('e' eq $cmd)
                   {print($_."\n");
                   }
                  else
                   {if(tcp($_))
                     {if('et' eq $cmd)
                       {print($_."\n");
                       }
                      else
                       {if('ets' eq $cmd)
                         {state($_,'s');
                         }
                        else
                         {state($_,'S');
                         }
                       }
                     }
                   }
                 }
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
