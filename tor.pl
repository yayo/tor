
# perl tor.pl t cached-descriptors cached-descriptors.new > n2
# perl tor.pl e15 state n2 > n3
# perl tor.pl s n2 $(cat n3) > n4

# list descriptors only IPs in cached-consensus
# perl tor.pl tg cached-descriptors cached-descriptors.new $(sed -ne 's/^r [0-9A-Za-z]\{1,19\} [0-9A-Za-z+\/]\{27\} [0-9A-Za-z+\/]\{27\} [0-9]\{4\}-[0-9]\{2\}-[0-9]\{2\} [0-9]\{2\}:[0-9]\{2\}:[0-9]\{2\} \([0-9]\{1,3\}[.][0-9]\{1,3\}[.][0-9]\{1,3\}[.][0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\}$/\1:\2/p' cached-consensus)

# perl tor.pl s cached-descriptors 128.31.0.34
# perl tor.pl s cached-descriptors 128.31.0.34:9101
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194:9090
# perl tor.pl s cached-descriptors cached-descriptors.new 128.31.0.34 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34 cached-descriptors.new  76.73.17.194
# perl tor.pl s 128.31.0.34 cached-descriptors 76.73.17.194 cached-descriptors.new
# perl tor.pl s 128.31.0.34 76.73.17.194 cached-descriptors cached-descriptors.new

# perl tor.pl S cached-descriptors 128.31.0.34
# s : Publish_Time
# S : Current_Time
# o : Ignore IP_NOT_FOUND

# perl tor.pl t cached-descriptors cached-descriptors.new | 7za a -mx9 -si cached-descriptors.7z
# Verify:
# sed -ne 's/^router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/\1.\2.\3.\4 \5/p' cached-descriptors cached-descriptors.new | sort | uniq | wc
# 7za x -so cached-descriptors.7z | perl tor.pl i - | wc

# perl tor.pl e1 state cached-descriptors cached-descriptors.new
#  e1n e1t e1tS
#  e1 : InUse
#  e2 : EntryGuardDownSince
#  e3 : InUse || EntryGuardDownSince
#  e4 : EntryGuardUnlistedSince
#  e5 : InUse || EntryGuardUnlistedSince
#  e6 : EntryGuardDownSince || EntryGuardUnlistedSince
#  e7 : InUse || EntryGuardDownSince || EntryGuardUnlistedSince
#  e8 : ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e9 : InUse || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e10 : EntryGuardDownSince || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e11 : InUse || EntryGuardDownSince || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e12 : EntryGuardUnlistedSince || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e13 : InUse || EntryGuardUnlistedSince || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e14 : EntryGuardDownSince || EntryGuardUnlistedSince || ( EntryGuardUnlistedSince && EntryGuardUnlistedSince )
#  e15 : ALL
#  n => count
#  t => TCP_Test
# perl tor.pl i cached-descriptors cached-descriptors.new | sed -e 's/:/ /g' | while read LINE ; do echo -n | nc -w 1 ${LINE} 2> /dev/null ; if [ 0 -eq $? ] ; then echo ${LINE} ; fi ; done

=begin SQL
CREATE TABLE router(id INTEGER PRIMARY KEY AUTOINCREMENT,ip integer(4) not null ,port integer(2) not null,unique(ip,port));
CREATE TABLE "connectivity"(router INTEGER not null references router(id) on delete RESTRICT on update CASCADE ,time integer(4) not null,test integer(1) not null,primary key(router,time));
SELECT (router.ip/16777216)||'.'||((router.ip%16777216)/65536)||'.'||((router.ip%65536)/256)||'.'||(router.ip%256)||':'||port/*,strftime('%Y-%m-%dT%H:%M:%SZ',max(time),'unixepoch')*/ FROM router inner join connectivity on router.id=connectivity.router and time>strftime('%s')-24*60*60 and test=2 GROUP BY id ORDER BY max(time) DESC;

PRAGMA foreign_keys=ON;
BEGIN TRANSACTION;
CREATE TABLE tmp(id INTEGER PRIMARY KEY AUTOINCREMENT,router INTEGER uniq not null references router(id) on delete RESTRICT on update CASCADE);
insert into sqlite_sequence values('tmp',(select min(id) from router where not exists(select * from router as router1 where router1.id=router.id+1)));
insert into tmp(router) select id from router where id>(select min(id)+1 from router where not exists(select * from router as router1 where router1.id=router.id+1));
update router set id=(select tmp.id from tmp where tmp.router=router.id) where exists(select * from tmp where router.id=tmp.router and router.id<>tmp.id);
drop table tmp;
update sqlite_sequence set seq=(select max(id) from router) where name='router';
select id-(select count(*) from router) from router where not exists(select * from router as router1 where router1.id=router.id+1);
COMMIT;

=end SQL
=cut


use strict;
use warnings;
use POSIX qw(mktime strftime);
use Time::Local;
use File::Basename;
use IO::Socket::INET;
use Sys::Mmap;

@_=gmtime();
my $timezone=Time::Local::timegm(@_)-Time::Local::timelocal(@_);

my %ips;
my %fingerprints;
my %entrys;

my $p_date='[0-9]{4}-[0-9]{2}-[0-9]{2}';
my $p_time='[0-9]{2}:[0-9]{2}:[0-9]{2}';
my $p_date_time=$p_date.' '.$p_time;
my $p_IP1='[0-9]{1,3}';
my $p_IP="$p_IP1(?:[.]$p_IP1){3}";
my $p_port='[0-9]{1,5}';
my $p_portrange="(?:$p_port(?:-$p_port){0,1})";
my $p_net='\/[0-9]{1,2}';
my $p_b64_64='[0-9A-Za-z+\/]{64}\n';
my $p_b64_64x2="(?:$p_b64_64){2}";
my $p_b64_64x2_60="${p_b64_64x2}[0-9A-Za-z+\/]{59}=\n";
my $p_b64_43='[0-9A-Za-z+\/]{43}';
my $p_b64_43e="$p_b64_43=\n";
my $p_b64_64x2_43="${p_b64_64x2}$p_b64_43e";
my $p_b64_64x2_11="${p_b64_64x2}[0-9A-Za-z+\/]{11}=\n";
my $p_version='[0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}';
my $p_nickname='[0-9A-Za-z]{1,19}';
my $p_OS='Windows|Linux|FreeBSD|OpenBSD|NetBSD|ElectroBSD|SunOS|Darwin|DragonFly|Bitrig|GNU|Very recent version of Windows|CYGWIN_NT';
my $p_header;

sub parse($)
 {if($_[0] !~ /${p_header}router ($p_nickname) ($p_IP) ($p_port) $p_port $p_port\n(?:identity-ed25519\n-----BEGIN ED25519 CERT-----\n$p_b64_64x2_60-----END ED25519 CERT-----\nmaster-key-ed25519 $p_b64_43\n){0,1}(?:or-address \[[0-9a-f:]{2,}\]:$p_port\n){0,1}platform Tor ($p_version)(?:-alpha|-beta|-rc|-alpha-dev|-beta-dev|-rc-dev|-dev){0,1} (?:\(git-[0-9a-f]{16}\) ){0,1}on (?:$p_OS)[^\n]{0,}\n(?:opt ){0,1}(?:protocols Link 1 2 Circuit 1|proto Cons=1-2 Desc=1-2 DirCache=1(?:-2){0,1} HSDir=1(?:-2){0,1} HSIntro=3(?:-4){0,1} HSRend=1-2 Link=1-4 LinkAuth=1(?:,3){0,1} Microdesc=1-2 Relay=1-2)\npublished (([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}))\n(?:opt ){0,1}fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})\nuptime [0-9]{1,9}\nbandwidth [0-9]{1,10} [0-9]{1,10} [0-9]{1,10}\n(?:(?:opt ){0,1}extra-info-digest [0-9A-F]{40}(?: $p_b64_43){0,1}\n){0,1}(?:(?:opt ){0,1}caches-extra-info\n){0,1}onion-key\n-----BEGIN RSA PUBLIC KEY-----\n$p_b64_64x2_60-----END RSA PUBLIC KEY-----\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n$p_b64_64x2_60-----END RSA PUBLIC KEY-----\n(?:onion-key-crosscert\n-----BEGIN CROSSCERT-----\n$p_b64_64x2_43-----END CROSSCERT-----\n){0,1}(?:ntor-onion-key-crosscert [01]\n-----BEGIN ED25519 CERT-----\n$p_b64_64x2_11-----END ED25519 CERT-----\n){0,1}(?:family(?: \$[0-9A-Fa-f]{40}){0,}(?: [^ \n]{1,}){0,}\n){0,1}(?:(?:opt ){0,1}hibernating 1\n){0,1}(?:(?:opt ){0,1}hidden-service-dir\n){0,1}(?:(?:opt ){0,1}allow-single-hop-exits\n){0,1}(?:contact [^\n]{1,}\n){0,1}(?:ntor-onion-key $p_b64_43e){0,1}(?:(?:reject|accept) (?:\*|$p_IP)(?:$p_net){0,1}:(?:\*|$p_portrange)\n(?:ipv6-policy (?:reject|accept) $p_portrange(?:,$p_portrange){0,}\n){0,1}){1,}(?:tunnelled-dir-server\n){0,1}(?:router-sig-ed25519 [0-9A-Za-z+\/]{86}\n){0,1}router-signature\n-----BEGIN SIGNATURE-----\n$p_b64_64x2_43-----END SIGNATURE-----\n$/)
   {warn('Malformed router:'."\n".$_[0]);
    exit();
   }
  else
   {my $published=POSIX::mktime($11,$10,$9,$8,$7-1,$6-1900,0,0,-1)+$timezone;
    if(POSIX::strftime('%Y-%m-%d %H:%M:%S',gmtime($published)) ne $5)
     {warn('Malformed published time: '.$_[0]);
      exit();
     }
    else
     {if(0==$3)
       {warn('0==ORPort');
        exit();
       }
      else
       {my $ORPort=$2;
        $ips{$ORPort}{$3}=0;
        $ORPort.=':'.$3;
        if(exists($_{$ORPort}) && $published==$_{$ORPort}[1] && $_[0] ne $_{$ORPort}[0])
         {die('Duplicate Router: '.$ORPort.' '.$published);
         }
        elsif(!exists($_{$ORPort}) || (exists($_{$ORPort}) && $published>$_{$ORPort}[1]))
         {my $fingerprint=$12.$13.$14.$15.$16.$17.$18.$19.$20.$21;
          $fingerprints{$fingerprint}{$ORPort}=0;
          @_=($_[0],$published,$fingerprint,$1,$4);
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
 {print('EntryGuard '.$_{$_[0]}[3].' '.$_{$_[0]}[2].' # '.$_[0]."\n".'EntryGuardAddedBy '.$_{$_[0]}[2].' '.$_{$_[0]}[4].' '.POSIX::strftime('%Y-%m-%d %H:%M:%S',('S' ne $_[1] ? gmtime($_{$_[0]}[1]):gmtime()))."\n");
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
    elsif('s' eq $ARGV[$_] || 'sg' eq $ARGV[$_] || 'S' eq $ARGV[$_] || 'Sg' eq $ARGV[$_])
     {$cmd=$ARGV[$_]; # build state from IPs
     }
    elsif('t' eq $ARGV[$_] || 'tg' eq $ARGV[$_])
     {$cmd=$ARGV[$_]; # remove duplicated IPs in cached-descriptors
     }
    elsif($ARGV[$_] =~  /^e([0-9]{1,2})(?:g){0,1}(?:n|t[sS]{0,1}){0,1}$/)
     {if(1>$1 || 15<$1)
       {warn('1<='.$1.'<=15');
        exit;
       }
      else
       {$cmd=$ARGV[$_];
       }
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
       {my $FILE;
        if(!open($FILE,'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {my $entry1=scalar(keys(%entrys));
          my $state;
          sysread($FILE,$state,-s $FILE);
          close($FILE);
          if("\n" ne substr($state,-1,1)) {die('CR != LAST_BYTE');}
          else
           {while($state =~ /^(EntryGuard .*?\n)(?:EntryGuard |BWHistoryReadEnds $p_date_time\r{0,1}\n|TorVersion Tor $p_version|$)/msg)
             {pos($state)-=length("\nEntryGuard ");
              my $e=$1;
              if($e !~ /^EntryGuard $p_nickname ([0-9A-F]{40})(?: (?:No){0,1}DirCache){0,1}(?: # $p_IP(?::$p_port){0,1}){0,1}\r{0,1}\n(EntryGuardDownSince $p_date_time $p_date_time\r{0,1}\n){0,1}(EntryGuardUnlistedSince $p_date_time\r{0,1}\n){0,1}EntryGuardAddedBy ([0-9A-F]{40}) $p_version $p_date_time\r{0,1}\n(?:EntryGuardPathBias(?: [0-9]{1,}[.][0-9]{6}){6}\r{0,1}\n){0,1}(?:EntryGuardPathUseBias(?: [0-9]{1,}[.][0-9]{6}){2}\r{0,1}\n){0,1}(.*){0,1}$/ms)
               {warn("Malformed: ".$e);
                exit();
               }
              else
               {if($1 ne $4) {die($1.' <> '.$4)}
                elsif(defined($5) && '' ne $5)
                 {warn('Malformed state:tail');
                  exit();
                 }
                else
                 {$entrys{$1}=0;
                  if(defined($2)) { $entrys{$1}|=1; }
                  if(defined($3)) { $entrys{$1}|=2; }
                  $entrys{$1}=1<<$entrys{$1};
                 }
               }
             }
            if(scalar(keys(%entrys))<=$entry1)
             {warn('NO "EntryGuard" found in state file: '.$ARGV[$_]);
              exit();
             }
           }
         }
       }
      else
       {my $f;
        if(!open($f,'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {binmode($f);
          my $m;
          if(!defined(mmap($m,0,PROT_READ,MAP_SHARED,$f,0)))
           {die();}
          else
           {my $p;
            if('router ' eq substr($m,0,7))
             {$p_header='^';
              $p="\nrouter ";
             }
            elsif('@downloaded-at ' eq substr($m,0,15))
             {$p_header="^\@downloaded-at $p_date_time\n\@source \"$p_IP\"\n(?:\@purpose bridge\n){0,1}";
              $p="\n\@downloaded-at ";
             }
            else
             {die('Malformed File Header');
             }
            my $s=0;
            my $b=length($p)-1;
            my $e=$b;
            while(-1!=($e=index($m,$p,$e)))
             {$e+=1;
              parse(substr($m,$s,$e-$s));
              $s=$e;
              $e+=$b;
             }
            parse(substr($m,$s));
            if(1!=munmap($m)){die();}
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
     {my @ip_not_found;
      foreach(keys(%ip))
       {if(exists($_{$_})){}
        elsif(exists($ips{$_}))
         {foreach my $port (keys(%{$ips{$_}}))
           {$ip{$_.':'.$port}=0;
           }
          delete($ip{$_});
         }
        else
         {push(@ip_not_found,$_);
          delete($ip{$_});
         }
       }
      if('g' ne substr($cmd,1,1) && 0!=scalar(@ip_not_found))
       {warn('Not_Found: '."\n".join("\n",@ip_not_found));
       }
      else
       {undef(%ips);
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
             {print('/* '.$_.' */INSERT OR IGNORE INTO router(ip,port) values('.$_[0].','.$_[1].');'.'INSERT INTO connectivity values((select id from router where ip='.$_[0],' and port=',$_[1].'),'.time().','.(tcp($_)?2:1).');'."\n");
             }
           }
         }
        elsif('i' eq $cmd || 'its' eq $cmd || 'itS' eq $cmd)
         {foreach(sort{ $_{$b}[1] <=> $_{$a}[1] || $b cmp $a }keys(%_))
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
        elsif('s' eq $cmd || 'sg' eq $cmd || 'S' eq $cmd || 'Sg' eq $cmd)
         {if(0==scalar(keys(%ip)))
           {warn('NO IP defined!');
            exit();
           }
          else
           {foreach(sort(keys(%ip)))
             {state($_,substr($cmd,0,1));
             }
           }
         }
        elsif('t' eq $cmd || 'tg' eq $cmd)
         {$_= 0==scalar(keys(%ip)) ? \%_ : \%ip ;
          foreach(sort{ $_{$a}[1] <=> $_{$b}[1] || $a cmp $b }(keys(%$_)))
           {print($_{$_}[0]);
           }
         }
        elsif($cmd =~ /^e([0-9]{1,2})(g){0,1}(n|t[sS]{0,1}){0,1}$/)
         {if(1>scalar(keys(%entrys)))
           {warn('state file NOT defined!');
            exit();
           }
          else
           {my ($mask,$ignore,$c,$n)=($1,$2,$3,0);
            my @notfound=();
            foreach(sort(keys(%entrys)))
             {if($entrys{$_}&$mask)
               {if(!exists($fingerprints{$_}))
                 {push(@notfound,$_);
                 }
                else
                 {foreach(sort(keys(%{$fingerprints{$_}})))
                   {if(defined($c))
                     {if('n' eq $c)
                       {$n++;
                       }
                      elsif('t' eq substr($c,0,1))
                       {if(tcp($_))
                         {if('t' eq $c)
                           {print($_."\n");
                           }
                          else
                           {state($_,substr($c,1,1));
                           }
                         }
                       }
                     }
                    else
                     {print($_."\n");
                     }
                   }
                 }
               }
             }
            if(0!=scalar(@notfound) && !defined($ignore))
             {warn("Not matched fingerprints:\n".join("\n",@notfound));
              exit();
             }
            else
             {if(defined($c) && 'n' eq $c)
               {print($n."\n");
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
 }
