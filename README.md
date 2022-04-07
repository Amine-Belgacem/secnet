# Secnet
Secnet is a multithreaded security and networking tool that supports processing tasks in mass. The tool provides the following utilities:
- `ping` TCP ping in single/mass.
- `scan` Scan network ports in single/mass over TCP.
- `lookup` Lookup domain names in single/mass.
- `rlookup` Reverse lookup IP address(es) in single/mass.
- `resolve` Rosolve domain name and return fetched response(s).
- `get` Send single/multiple GET request(s) to single/multiple hosts.
- `myip` Fetch external IP address.
- `mywlan` Discover devices connected to Wi-Fi network.

## Download & Install
Clone repository.

    git clone https://github.com/Amine-Belkacem/Secnet.git
Run in command-line.

    /release/secnet-v0.9.exe -help

## Usage
Usage: `secnet [command] [options...]`

**Network Port Scanner over TCP**

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

**Ping over TCP**

    Command: ping [options..]
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

**DNS Lookup Tool**

    Command: lookup [options..]
    -domain     Domain name(s) to lookup in SECNET::DNS format.
                SECNET::DNS Format allowed values: 
                    - DNS (e.g. 'www.google.com')
                    - DNS-File in file URI scheme (e.g. 'file://example.txt)'
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

**Reverse DNS Lookup Tool**

    Command: rlookup [options..]
    -ip         IP address(s) to reverse lookup in SECNET::IP format.
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

**DNS Resolver**

    Command: resolve [options..]
    -domain     Domain name(s) to resolve in SECNET::DNS format.
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

**External IP Address Discovery Tool**

    Command: myip [options..]
    -timeout    Second(s) to wait before abandoning request (e.g. '10')

**Wi-fi Connected Devices Discovery Tool**

    Command: mywlan [options..]
    -timeout    Second(s) to wait before abandoning request (e.g. '10')
    -thread     Number of worker threads (e.g. '5')
    -output     Output file path (e.g. './example.txt')

**GET Request Sender**

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
