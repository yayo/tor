
# perl tor.pl s cached-descriptors 128.31.0.34
# perl tor.pl s cached-descriptors 128.31.0.34:9101
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34:9101 76.73.17.194:9090
# perl tor.pl s cached-descriptors cached-descriptors.new 128.31.0.34 76.73.17.194
# perl tor.pl s cached-descriptors 128.31.0.34 cached-descriptors.new  76.73.17.194
# perl tor.pl s 128.31.0.34 cached-descriptors 76.73.17.194 cached-descriptors.new
# perl tor.pl s 128.31.0.34 76.73.17.194 cached-descriptors cached-descriptors.new

# perl tor.pl s old cached-descriptors 128.31.0.34

# perl tor.pl t cached-descriptors cached-descriptors.new > cached-descriptors.new.new
# Verify:
# sed -ne 's/^router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/\1.\2.\3.\4 \5/p' cached-descriptors cached-descriptors.new | sort | uniq | wc
# sed -ne 's/^router [^ ]\{1,\} \([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\)[.]\([0-9]\{1,3\}\) \([0-9]\{1,5\}\) [0-9]\{1,5\} [0-9]\{1,5\}$/\1.\2.\3.\4 \5/p' cached-descriptors.new.new | sort | uniq | wc


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
  if($_[0] !~ /^\@downloaded-at [0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\n\@source "[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}"\nrouter ([0-9A-Za-z]{1,19}) ([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3}) ([0-9]{1,}) [0-9]{1,} [0-9]{1,}\nplatform Tor ([0-9]{1,}[.][0-9]{1,}[.][0-9]{1,}[.][0-9]{1,})(?:-alpha|-beta|-alpha-dev|-beta-dev|-rc|-dev){0,1} (?:\(git-[0-9a-f]{16}\) ){0,1}on (?:Windows|Linux|FreeBSD|OpenBSD|NetBSD|SunOS|Darwin|DragonFly|Very recent version of Windows)[^\n]{0,}\nopt protocols Link 1 2 Circuit 1\npublished ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\nopt fingerprint ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4}) ([0-9A-F]{4})\nuptime [0-9]{1,9}\nbandwidth [0-9]{1,10} [0-9]{1,10} [0-9]{1,10}\n(?:opt extra-info-digest [0-9A-F]{40}\n){0,1}(?:opt caches-extra-info\n){0,1}onion-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\nsigning-key\n-----BEGIN RSA PUBLIC KEY-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{59}=\n-----END RSA PUBLIC KEY-----\n(?:family(?: \$[0-9A-Fa-f]{40}){0,}(?: [^ \n]{1,}){0,}\n){0,1}(?:opt hibernating 1\n){0,1}(?:opt hidden-service-dir\n){0,1}(?:opt allow-single-hop-exits\n){0,1}(?:contact [^\n]{1,}\n){0,1}(?:(?:reject|accept) (?:\*|[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3})(?:\/[0-9]{1,2}){0,1}:(?:\*|[0-9]{1,5}(?:-[0-9]{1,5}){0,1})\n){1,}router-signature\n-----BEGIN SIGNATURE-----\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{64}\n[0-9A-Za-z+\/]{43}=\n-----END SIGNATURE-----\n$/)
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
        my $fingerprint=$14.$15.$16.$17.$18.$19.$20.$21.$22.$23;
        $fingerprints{$fingerprint}{$ORPort}=0;
        if(!exists($_{$ORPort})||(exists($_{$ORPort})&&$_{$ORPort}[0]<$published))
         {@_=($published,$_[0],$fingerprint,$1,$7);
          $_{$ORPort}=\@_;
         }
       }
     }
   }
 }

sub state($$)
 {my @t;
  if(0!=$_[1])
   {@t=gmtime($_{$_[0]}[0]);
   }
  else
   {@t=gmtime();
   }
  print('EntryGuard '.$_{$_[0]}[3].' '.$_{$_[0]}[2].' # '.$_[0]."\n".'EntryGuardAddedBy '.$_{$_[0]}[2].' '.$_{$_[0]}[4].' '.POSIX::strftime('%Y-%m-%d %H:%M:%S',@t)."\n");
 }

if(1>scalar(@ARGV))
 {warn('Usage: tor.pl cached-descriptors');
  exit();
 }
else
 {my $cmd;
  my $old=0;
  my $i=0;
  my @files;
  my %ip;
  for($_=0;$_<scalar(@ARGV);$_++)
   {
    if($ARGV[$_] eq 's')
     {$cmd='s'; # build state from IPs
     }
    elsif($ARGV[$_] eq 't')
     {$cmd='t'; # remove duplicated IPs in cached-descriptors
     }
    elsif($ARGV[$_] eq 'i')
     {$cmd='i'; # list IPs in cached-descriptors
     }
    elsif($ARGV[$_] eq 'e')
     {$cmd='e'; # list IPs in state
     }
    elsif($ARGV[$_] eq 'old')
     {$old=1;
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
     {
      if('state' eq basename($ARGV[$_]))
       {if(!open(FILE,'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {while(my $line=<FILE>)
           {if($line =~ /^EntryGuard [0-9A-Za-z]{1,19} ([0-9A-F]{40})$/)
             {$entrys{$1}=0;
             }
           }
          close(FILE);
         }
       }
      else
       {if(!open($files[$i],'<',$ARGV[$_]))
         {warn('Can NOT open file: '.$ARGV[$_]);
          exit();
         }
        else
         {$i++;
         }
       }
     }
   }
  if(!defined($cmd))
   {warn('NO Command defined!');
    exit();
   }
  else
   {if(1>scalar(@files))
     {warn('NO file defined!');
      exit();
     }
    else
     {
      foreach $i (@files)
       {if(defined($_=readline($i)))
         {
          if($_ !~ /^\@downloaded-at ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
           {warn('UnKnown LINE1: '.$_);
            exit();
           }
          else
           {while(my $line=readline($i))
             {if($line !~ /^\@downloaded-at /)
               {$_.=$line;
               }
              else
               {if($line !~ /^\@downloaded-at ([0-9]{4})-([0-9]{2})-([0-9]{2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})$/)
                 {warn('UnKnown @downloaded-at: '.$line);
                  exit();
                 }
                else
                 {parse($_);
                  $_=$line;
                 }
               }
             }
            parse($_);
           }
         }
        close($i);
       }
      if('s' eq $cmd)
       {
        if(0==scalar(keys(%ip)))
         {warn('NO IP defined!');
          exit();
         }
        else
         {foreach(keys(%ip))
           {if(exists($_{$_}))
             {state($_,$old);
             }
            elsif(exists($ips{$_}))
             {foreach my $port (keys(%{$ips{$_}}))
               {state($_.':'.$port,$old);
               }
             }
            else
             {warn('Not Found: '.$_);
              exit;
             }
           }
         }
       }
      elsif('t' eq $cmd)
       {while((my $ORPort,$_)=each(%_))
         {print($$_[1]);
         }
       }
      elsif('i' eq $cmd)
       {foreach(keys(%_))
         {print($_."\n");
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
