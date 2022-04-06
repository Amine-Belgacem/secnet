#!/usr/bin/perl

# Secnet - Multithreaded Security and Network Tool
# Copyright (C) 2012 Amine Belkacem

# The tool proposes the following utilities:
# - [ping] TCP ping in single/mass.
# - [scan] Scan network ports in single/mass over TCP.
# - [lookup] Lookup domain names in single/mass.
# - [rlookup] Reverse lookup IP addreses in single/mass.
# - [resolve] Rosolve domain name and return fetched response(s).
# - [get] Send single/multiple GET request(s) to single/multiple hosts.
# - [myip] Fetch external IP address.
# - [mywlan] Discover devices connected to Wifi network.

# Note: The tool is for Win64/32, Adjustements needed for Linux.

# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool. The author accepts no liability
# for damage caused by this tool. If these terms are not acceptable to you, then
# you are not permitted to use this tool.

use strict;
use warnings;
use 5.010;
use Net::IP;
use Getopt::Long;
use File::Basename;
use IO::Socket::INET;
use threads;
use Thread::Queue;
use Net::Ping;
use Net::DNS::Resolver;
use LWP::UserAgent;
use IO::Handle;
use Data::Validate::URI;

# Helper subroutines:

# Trim leading and trailing spaces from a string.
sub trim { 
    my $string = shift; 
    $string =~ s/^\s+|\s+$//g; 
    return $string
}

# Join a Hashref into a string
sub joinHashref {
    my $hashref = shift;
    my $sep = shift;
    my $innerSep = shift;
    return join($sep, map { 
        $_.$innerSep.$hashref->{$_} 
    } sort keys %{$hashref})
}

# Extract file path from a file URI scheme
sub extractFilePath {
    my $string = shift;
    my $path = substr($string, 7, length($string));
    return $path
}

# Type validation subroutines:

# Check if value exists in an array.
sub isInArray {
    my @array = @{$_[0]};
    my $value = $_[1];
    my %arrayHash = map { $_ => 1 } @array;
    return exists($arrayHash{$value})
}

# Check if string is a file URI scheme
sub isFileURI {
    my $string = shift;
    return (rindex $string, "file://", 0) == 0
}

# Check if directory exists.
sub isDirectory {
    my $directory = dirname(shift);
    die "'$directory' directory does not exist.\n" if (! -d $directory);
    return 1
}

# Check if file exists, not empty, readeable and writeable.
sub isFile {
    my $filePath = shift;
    my $fileName = basename($filePath);
    die "'$fileName' file does not exist.\n" if (! -e $filePath);
    die "'$fileName' file is empty.\n" if (-z $filePath);
    die "'$fileName' file is not readeable.\n" if (!-r $filePath);
    die "'$fileName' file is not writeable.\n" if (!-w $filePath);
    return 1
}

# Check if argument is a valid IP address.
sub isIP {
    my $ip = shift;
    my $ipRegex = qr/
        (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]
        |2[0-4][0-9]|[01]?[0-9][0-9]?)
    /x;
    return ("$ip" =~ /(\b^$ipRegex\b$)/) ? 1 : 0
}

# Check if argument is a valid domaine name.
sub isDomain {
    my $domain = shift;
    my $domainRegex = qw/^((([a-z]|[0-9]|\-)+)\.)+([a-z])+$/;
    return ($domain =~ /(\b^$domainRegex\b$)/) ? 1 : 0
}

# Check if argument is a valid network port.
sub isPort {
    my $port = shift;
    my $portRegex = qr/
        6553[0-5]|655[0-2]\d|65[0-4]\d\d|
        6[0-4]\d\d\d|[1-5]\d\d\d\d|[1-9]\d?\d?\d?|0
    /x;
    return (($port =~ /(\b^$portRegex\b$)/) && $port > 0) ? 1 : 0
}

# Check if argument is a valid MAC address.
sub isMAC {
    my $mac = shift;
    my $macRegex = qr/
        (?:(?:[0-9a-fA-F]{1,2})(?:-|:)(?:[0-9a-fA-F]{1,2})(?:-|:)
        (?:[0-9a-fA-F]{1,2})(?:-|:)(?:[0-9a-fA-F]{1,2})(?:-|:)
        (?:[0-9a-fA-F]{1,2})(?:-|:)(?:[0-9a-fA-F]{1,2}))
    /x;
    return ($mac =~ /(\b$macRegex\b)/) ? $1 : 0
}

# Check if argument is URL.
sub isURL {
    my $url = shift;
    my $validator = new Data::Validate::URI();
    return ($validator->is_http_uri($url) or $validator->is_https_uri($url))
}

# Check if argument contains illegal URI chars.
sub isURLPath {
    my $url = shift;
    my $urlCharsRegex = qr/[^a-z0-9\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\.\-\_\~\%]/i;
    return !($url =~ /($urlCharsRegex)/) ? $url : 0
}

# File related subroutines:

# Open file and return file handle.
sub openFile {
    my $filePath = shift;
    my $mode = shift;
    my $fileHandle;
    open ($fileHandle, $mode, $filePath) or
        die "Could not open file '".basename($filePath).".': $!\n";
    return $fileHandle
}

# Close file handle.
sub closeFile {
    my $fileHandle = shift;
    my $filePath = shift;
    close $fileHandle or
        die "Could not close file '".basename($filePath).".': $!\n";
    return 1
}

# Write string to file.
sub toFile {
    my $fileHandle = shift;
    my $string = shift;
    print {$fileHandle} $string;
    return 1
}

# Read file lines into an array.
sub readFileIntoArray {
    my $filePath = shift;
    my $fileHandle = openFile($filePath, "<:encoding(utf8)");
    chomp(my @array = <$fileHandle>);
    closeFile($fileHandle, $filePath);
    return @array
}

# Get content of file and validate lines.
sub getFileContent {
    isFile(my $filePath = shift);
    my $validate = shift;
    my $filename = basename($filePath);
    my @fileContent = readFileIntoArray($filePath);
    my @contentList;
    foreach (@fileContent) {
        if (&$validate(trim($_))) { push(@contentList, trim($_)) }
    }
    if (scalar(@contentList) == 0) { die "0 records found in '$filename'\n" }
    print scalar(@contentList)." records imported from '$filename'\n";
    return @contentList       
}

# Loader and generator subroutines:

# Check output directory and return path.
sub getOutput {
    my $path = shift;
    isDirectory($path);
    return $path
}

# Return port range array if argument is valid.
sub getPortRange  {
    my $range = shift;
    my $error = "Option port requires valid network port range.\n";
    die $error if (!$range =~ /-/);
    my ($lowerPort, $upperPort) = split(/-/, $range);
    $lowerPort = trim($lowerPort);
    $upperPort = trim($upperPort);
    die $error if !isPort($lowerPort) || !isPort($upperPort);
    die $error if $lowerPort > $upperPort;
    return ($lowerPort, $upperPort)
}

# Load from file or generate ports from argument.
sub getPorts {
    my $port = trim(shift);
    my $path;
    return getFileContent($path, \&isPort) 
        if (isFileURI($port) && isFile($path = extractFilePath($port)));
    if ($port =~ /-/ && (my @portRange = getPortRange($port))) {
        my @ports;
        for (my $count = $portRange[0]; $count <= $portRange[1]; $count++){
            push(@ports, $count)
        }
        return @ports;
    }
    die "Invalid network port in port option.\n" if !isPort($port);
    return ($port)   
}

# Load from file or generate IPs from argument.
sub getIPs {
    my $ip = trim(shift);
    my $path;
    return getFileContent($path, \&isIP) 
        if (isFileURI($ip) && isFile($path = extractFilePath($ip)));
    my $netIP = new Net::IP($ip);
    die ucfirst(lc(Net::IP::Error))."\n" if defined Net::IP::Error;
    Net::IP::ip_is_ipv4($netIP->ip()) 
        or die "Only IPv4 is supported in ip option.\n";
    my @ips;
    do { push(@ips, $netIP->ip()) } while (++$netIP);
    return @ips
}

# Load from file or return domain from argument.
sub getDomains {
    my $domain = trim(shift);
    my $path;
    return getFileContent($path, \&isDomain) 
        if (isFileURI($domain) && isFile($path = extractFilePath($domain)));
    die "Invalid domain name format in domain option.\n" 
        if (!isDomain($domain));
    return ($domain)
}

# Load dork file or return dork.
sub getDorks {
    my $dork = trim(shift);
    my $path;
    return getFileContent($path, \&isURLPath) 
        if (isFileURI($dork) && isFile($path = extractFilePath($dork)));
    die "Invalid dork format in dork option.\n" 
        if (!isURLPath($dork));
    return ($dork)
}

# Load URL file or return URL.
sub getURLs {
    my $url = trim(shift);
    my $path;
    return getFileContent($path, \&isURL) 
        if (isFileURI($url) && isFile($path = extractFilePath($url)));
    die "Invalid url format in url option.\n" 
        if (!isURL($url));
    return ($url)
}

# Main processing subroutine:
# Feed tasks to threads and execute callback.
sub process {
    my @tasks = @{$_[0]};
    my $output = $_[1];
    my $callback = $_[2];
    my $threads = $_[3];
    my $queue = Thread::Queue->new(@tasks);
    $queue->end();
    print "> Processing ".scalar(@tasks). " task(s)...\n\n";
    my @threads = map {
        threads->create(sub {
            my $fileHandle = openFile($output, ">>") if $output;
            while (defined(my $task = $queue->dequeue())) {
                &$callback($task, $fileHandle)
            }
            closeFile($fileHandle) if $fileHandle;
        });
    } 1 .. $threads;
    $_->join foreach (@threads);
    print "\n> Processing ended: ".scalar(@tasks)." task(s) finished.\n";
    print "> Results exported to '$output'\n" if $output
}

# [scan] related subroutines:

# Connect to host on port over TCP.
sub tcpConnect {
    my ($ip, $port, $timeout) = @_;
    my $socket = IO::Socket::INET->new(
        PeerAddr => $ip,
        PeerPort => $port,
        Proto    => 'tcp',
        Timeout  => $timeout
    );
    return defined $socket
}

# Validate and return [scan] options.
sub geScanOptions {
    my @defaultPorts = ("21", "22", "23", "53", "80", "111", "135", "139", "445");
    my @defautips = ("127.0.0.1");
    my %options = (
        'ips' => \@defautips,
        'ports' => \@defaultPorts,
        'thread' => 2, 
        'timeout' => 2
    );
    GetOptions (
        "ip=s" => sub {@{$options{'ips'}} = getIPs($_[1])},
        "port=s" => sub {@{$options{'ports'}} = getPorts($_[1])},
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options
}

# Validate arguments, prepare tasks and run [scan] threads.
sub scan () {
    print "\n[scan] Network Port Scanner over TCP\n\n";
    my %options = geScanOptions();
    my @tasks;
    for my $ip (@{$options{'ips'}}) {
        for my $port (@{$options{'ports'}}) { 
            my @task = ($ip, $port, $options{'timeout'});
            push (@tasks, \@task)
        }
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        my $ipPort = "@$task[0]:@$task[1]";
        if (tcpConnect(@$task)) {
            toFile($fileHandle, "$ipPort\n") if $fileHandle;
            print "- $ipPort => status:open port-no:@$task[1]\n"
        } else {
            print "- $ipPort => status:close\n"
        }    
    }, $options{'thread'})
}

# [ping] related subroutines:

# Ping host over TCP.
sub pingHost {
    my $ip = shift;
    my $timeout = shift;
    my $netPing = Net::Ping->new();
    return my ($ret, $duration) = $netPing->ping($ip, $timeout)
}

# Validate and return [ping] options.
sub getPingOptions {
    my @defautIPs = ("127.0.0.1");
    my %options = (
        'ips' => \@defautIPs,
        'thread' => 2, 
        'timeout' => 5
    );
    GetOptions (
        "ip=s" => sub {@{$options{'ips'}} = getIPs($_[1])},
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options    
}

# Validate arguments, prepare tasks and run [ping] threads.
sub ping {
    print "\n[ping] Ping over TCP\n\n";
    my %options = getPingOptions();
    my @tasks;
    for my $ip (@{$options{'ips'}}) {
        my @task = ($ip, $options{'timeout'});
        push (@tasks, \@task)
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        my @result = pingHost(@$task);
        if ($result[0] == 1) {
            my $respTime = sprintf("%.2f", $result[1]);
            toFile($fileHandle, @$task[0]."\n") if $fileHandle;
            print "- @$task[0] => status:alive resp-time:$respTime"."s\n"
        } else {
            print "- @$task[0] => status:timed-out\n"
        }      
    }, $options{'thread'}) 
}

# [lookup] related subroutine:

# lookup a domain name's IP address.
sub lookupDomain {
    my $domain = shift;
    my $inet_aton = inet_aton($domain);
    return 0 if not defined $inet_aton;
    return inet_ntoa($inet_aton)
}

# Validate and return [lookup] options.
sub getLookupOptions {
    my @defautDomains = ("localhost");
    my %options = (
        'domains' => \@defautDomains,
        'thread' => 2,
    );
    GetOptions (
        "domain=s" => sub {@{$options{'domains'}} = getDomains($_[1])},       
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
    ) or die $SECNET::usage;
    return %options    
}

# Validate arguments, prepare tasks and run [lookup] threads.
sub lookup {
    print "\n[lookup] DNS Lookup Tool\n\n";
    my %options = getLookupOptions();
    my @tasks;
    for my $domain (@{$options{'domains'}}) {
        my @task = ($domain);
        push (@tasks, \@task)
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        if (my $result = lookupDomain(@$task)) {
            print "- @$task[0] => status:resolved ip-addr:$result\n";
            toFile($fileHandle, "$result\n") if $fileHandle
        } else {
            print "- @$task[0] => status:unresolved\n"
        }
    }, $options{'thread'})  
}

# Reverse lookup an IP address's domaine name.
sub dnsReverseLookup {
    my $ip = shift;
    my $inet_aton = inet_aton($ip);
    return 0 if not defined $inet_aton;
    my $domain = gethostbyaddr($inet_aton, AF_INET);
    return $domain
}

# Validate and return [rlookup] options.
sub getRlookupOptions {
    my @defautIPs = ("localhost");
    my %options = (
        'ips' => \@defautIPs,
        'thread' => 2,
    );
    GetOptions (
        "ip=s" => sub {@{$options{'ips'}} = getIPs($_[1])},            
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
    ) or die $SECNET::usage;
    return %options    
}

# Validate arguments, prepare tasks and run [rlookup] threads.
sub rlookup {
    print "\n[rlookup] Reverse DNS Lookup Tool\n\n";
    my %options = getRlookupOptions();
    my @tasks;
    for my $ip (@{$options{'ips'}}) {
        my @task = ($ip);
        push (@tasks, \@task)
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        if (my $result = dnsReverseLookup(@$task)) {
            print "- @$task[0] => status:resolved dmn-name:$result\n";
            toFile($fileHandle, "$result\n") if $fileHandle;                
        } else {
            print "- @$task[0] => status:unresolved\n"
        }
    }, $options{'thread'})  
}

# [resolve] related subroutines:

# Resolve a domain name and return replies.
sub dnsResolve {
    my $domain = shift;
    my $timeout = shift;
    my $resolver = Net::DNS::Resolver->new;
    $resolver->udp_timeout($timeout);
    $resolver->tcp_timeout($timeout);
    if (my $result = $resolver->search($domain)) {
        my @answer = $result->answer;
        my @replies;
        foreach (@answer) {
            my %option;
            $option{'owner'} = $_->owner if (defined $_->{'owner'});
            $option{'cname'} = $_->cname if (defined $_->{'cname'});
            $option{'address'} = $_->address if (defined $_->{'address'});
            $option{'type'} = $_->type if (defined $_->{'type'});
            push (@replies, \%option)
        }
        return @replies;
    }
    return ()
}

# Validate and return [resolve] options.
sub getResolveOptions {
    my @defautDomains = ("localhost");
    my %options = (
        'domains' => \@defautDomains,
        'thread' => 2,
        'timeout' => 5,
    );
    GetOptions (
        "domain=s" => sub {@{$options{'domains'}} = getDomains($_[1])},        
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options
}

# Validate arguments, prepare tasks and run [resolve] threads.
sub resolve {
    print "\n[resolve] DNS Resolver\n\n";
    my %options = getResolveOptions();
    my @tasks;
    for my $domain (@{$options{'domains'}}) {
        my @task = ($domain, $options{'timeout'});
        push (@tasks, \@task)
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        my @result = dnsResolve(@$task);
        if (scalar @result > 0) {
            my (@replies, $prefix);
            foreach (@result) {
                $prefix = "+ [Reply] => ";
                push (@replies, $prefix.joinHashref($_, " ", ":"));
            }
            my $reply = "\n".join("\n", @replies);
            print "- @$task[0] => status:resolved $reply\n";
            toFile($fileHandle, "@$task[0] => status:resolved $reply\n") if $fileHandle                
        } else {
            print "- @$task[0] => status:unresolved\n"
        }
    }, $options{'thread'});   
}

# [myip] related subroutines:

# Validate and return [myip] options.
sub getMyipOptions {
    my @defaultProviders = (
        "http://icanhazip.com",
        "http://api.ipify.org?format=text",
        "http://myexternalip.com/raw",
    );
    my %options = (
        'timeout' => 5,
        'providers'=> \@defaultProviders
    );
    GetOptions (
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options    
}

# Get external IP address from providers.
sub myip {
    print "\n[myip] External IP Address Discovery Tool\n\n";
    my %options = getMyipOptions();
    my $agent = LWP::UserAgent->new(timeout => $options{'timeout'});
    print "> Requesting external IP address from providers...\n\n";
    foreach (@{$options{'providers'}}) {
        print "- $_ => ";
        my $response = $agent->get($_);
        if ($response->is_success) {
            my $publicIP = $response->decoded_content;
            isIP($publicIP) ? 
                print "ip-addr:".trim($publicIP)."\n":
                print "ip-addr:not-found\n"
        } else {
            print "\n> (".$response->code.") Failed request to provider: $_\n"
        }
    }
    print "\n> Requesting ended.\n";
}

# [mywlan] Related subroutines:

# Run an external software and parse the output with a callback.
sub run {
    my $filepath = shift;
    my $command = shift;
    my $callback = shift;
    my $result;
    open(my $fileHandle, "$filepath $command |") 
        or die "Unable to run '$filepath'.\n";
    while (<$fileHandle>) {
        last if ($result = &$callback($_))
    }
    return $result
}

# Run 'netsh.exe' and search for active Wi-Fi interface name.
sub getWifiName {
    my @names;
    my $command = "wlan show interfaces";
    my $result = run("netsh.exe", $command, sub {
        my $line = shift;
        push (@names, $1) if ($line =~ /\b[nN]ame\s*:\s(.*)\b/);
        return $line =~ /\b[Ss]tate\s*:\sconnected\b/
    });
    die "Unable to get current Wi-Fi interface name.\n" if (!$result);
    return $names[-1]   
}

# Run 'netsh.exe' and search for 'Subnet Prefix'.
sub getSubnetPrefix {
    my $interface = shift;
    my $command = "interface ip show addresses $interface";
    my $result = run("netsh.exe", $command, sub {
        my $line = shift;
        return $1 if ($_ =~ /\bSubnet\sPrefix:\s*([0-9.]+\/[0-9]+)\b/)
    });
    die "Unable to get current subnet prefix.\n" if (!$result);
    return $result
}

# Run 'netsh.exe' and search for 'Gateway'
sub getWifiGateway {
    my $interface = shift;
    my $command = "interface ip show addresses $interface";
    my $result = run("netsh.exe", $command, sub {
        my $line = shift;
        return $1 if ($_ =~ /\bDefault\sGateway:\s*([0-9.]+)\b/)
    });
    return $result
}

# Run 'arp.exe' and search for Mac address.
sub getMACbyIP {
    my $ip = shift;
    my $command = "$ip -a";
    my $result = run("arp.exe", $command, sub {
        my $line = shift;
        if (my $mac = isMAC($_)) { return $mac } 
    });
    return $result ? $result : "unknown"
}

# Validate and return [mywlan] options.
sub getMywlanOptions {
    my %options = (
        'timeout' => 5,
        'thread' => 10,
    );
    GetOptions (
        "output=s" => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options    
}

# Discover devices connected to Wi-Fi.
sub mywlan {
    print "\n[mywlan] Wi-fi Connected Devices Discovery Tool\n\n";
    my %options = getMywlanOptions();
    print "> Getting active Wi-Fi interface info...\n\n";
    my $name = getWifiName();
    print "- Wifi-interface => '".$name."'\n";
    my $subnet = getSubnetPrefix($name);
    print "- Subnet-prefix => ".$subnet."\n";
    print "- Gateway => ".getWifiGateway($name)."\n\n";    
    my @tasks;
    for my $ip (getIPs($subnet)) {
        my @task = ($ip, $options{'timeout'});
        push (@tasks, \@task);
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        my @result = pingHost(@$task);
        if ($result[0] == 1) {
            my $macAddr = getMACbyIP(@$task[0]);
            my $hostname = gethostbyaddr(inet_aton(@$task[0]), AF_INET);
            $hostname = "unknown" if (!$hostname);
            my $respTime = sprintf("%.2f", $result[1]);
            toFile($fileHandle, @$task[0]."\n") if $fileHandle;
            print "- @$task[0] => name:$hostname mac-addr:$macAddr\n"
        } {}
    }, $options{'thread'})
}

# [get] Related subroutines:

# Fetch URL content.
sub requestURL {
    my $url = shift;
    my $dork = shift;
    my $timeout = shift;
    my $agent = LWP::UserAgent->new(timeout =>$timeout);
    my $request = new HTTP::Request('GET', $url.'/'.$dork);
    my $response = $agent->request($request);
    return ($response->code, $response->decoded_content) 
        if ($response->is_success);
    return ($response->code)
}

# Validate and return [get] options.
sub getGetOptions {
    my @defaultURLs = ('http://google.com');
    my @defaultDorks = ('');
    my %options = (
        'urls' => \@defaultURLs,
        'dorks' => \@defaultDorks,
        'timeout' => 5,
        'thread' => 2,
    );
    GetOptions (
        "url=s" => sub {@{$options{'urls'}} = getURLs($_[1])}, 
        "dork=s" => sub {@{$options{'dorks'}} = getDorks($_[1])}, 
        "output=s"  => sub {$options{'output'} = getOutput($_[1])},
        "threads=i" => \$options{'thread'},
        "timeout=i" => \$options{'timeout'},
    ) or die $SECNET::usage;
    return %options    
}

# Send GET request to single/mass hosts.
sub get {
    print "\n[get] GET Request Sender\n\n";
    my %options = getGetOptions();
    my @tasks;
    for my $url (@{$options{'urls'}}) {
        for my $dork (@{$options{'dorks'}}) { 
            my @task = ($url, $dork, $options{'timeout'});
            push (@tasks, \@task)
        }
    }
    process(\@tasks, $options{'output'}, sub {
        my ($task, $fileHandle) = @_;
        my @result = requestURL(@$task);
        if ($result[1]) {
            print "- @$task[0]/@$task[1] => status:$result[0] \n";
            toFile($fileHandle, "@$task[0]/@$task[1]\n") if $fileHandle                
        } else {
            print "- @$task[0]/@$task[1] => status:$result[0] \n"
        }
    }, $options{'thread'}) 
}

# Main:

# Get main command and call subroutine.
sub getCommand {
    my $cmd = shift;
    my @commands = (
        "scan", 
        "ping", 
        "lookup", 
        "rlookup", 
        "resolve", 
        "get", 
        "myip", 
        "mywlan"
    );
    if (defined $cmd && isInArray(\@commands, $cmd)) {
        scan()    if $cmd eq 'scan';
        ping()    if $cmd eq 'ping';
        lookup()  if $cmd eq 'lookup';
        rlookup() if $cmd eq 'rlookup';
        resolve() if $cmd eq 'resolve';
        get()     if $cmd eq 'get';
        myip()    if $cmd eq 'myip';
        mywlan()  if $cmd eq 'mywlan';
    } else {
        if (not defined $cmd) { 
            print "Error: Missing command, unable to continue.\n";
            print "-> exit.\n";
            die $SECNET::usage
        }
        print "Error: Unknown command, please select a supported command.\n";
        print "-> exit.\n";
        die $SECNET::usage
    }
}

# Catch die and warn signals.
sub errorWrap {
    my $error = $_[0];
    chomp($error);
    $error .= '.' if (substr($error, length($error) - 1, 1) ne '.');
    print "Error: ".$error."\n";
    print "-> exit.\n"
}
$SIG{__WARN__} = \&errorWrap;

# Usage information global variable.
$SECNET::usage = <<EOF;

Usage: secnet [command] [options...]

Available commands: [scan, ping, lookup, rlookup, resolve, myi,p mywlan, get]

Command: scan [options..]

    -ip         IP address(es) of the host to scan in SECNET::IP format.
                SECNET::IP Format allowed values:
                    - IP (e.g. '127.0.0.1');
                    - IP-Range (e.g. '127.0.0.1-127.0.0.255)'
                    - IP-Subnet-Prefix (e.g. '127.0.0.1/24)'
                    - IP-File in file URI scheme (e.g. 'file://example.txt)'
    -port       Port(s) nubmer of the host to scan in SECNET-PORT format.
                SECNET::PORT Format allowed values:
                    - Port (e.g. '80')
                    - Port-Range (e.g. '10-200')
                    - Port-File in file URI scheme(e.g. 'file://example.txt)'
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: ping [options..]

    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: lookup [options..]

    -domain     Domain name(s) to lookup in SECNET::DNS format.
                SECNET::DNS Format allowed values: 
                    - DNS (e.g. 'www.google.com')
                    - DNS-File in file URI scheme (e.g. 'file://example.txt)'
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: rlookup [options..]

    -ip         IP address(s) to reverse lookup in SECNET::IP format.
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: resolve [options..]

    -domain     Domain name(s) to resolve in SECNET::DNS format.
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: myip [options..]

    -timeout    Second(s) to wait before abandoning request (e.g. '10')

Command: mywlan [options..]

    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

Command: get [options..]

    -url        URL(s) to get in SECNET::URL format.
                SECNET::URL Format allowed values: 
                    - URL (e.g. 'http://www.google.com')
                    - URL-File in file URI scheme (e.g. 'file://example.txt)'
    -dork       Dork(s) to get in SECNET::DORK format.
                SECNET::DORK Format allowed values: 
                    - DORK (e.g. 'admin/login.php?')
                    - DORK-File in file URI scheme (e.g. 'file://example.txt)'
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')
EOF

getCommand($ARGV[0]);