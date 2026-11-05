# Secnet

A multithreaded Perl networking toolkit with TCP checks, DNS lookups, HTTP requests, and local network discovery.

## Commands

- `ping` and `scan`: TCP connectivity and port checks.
- `lookup`, `rlookup`, and `resolve`: forward and reverse DNS queries.
- `get`: HTTP GET requests.
- `myip` and `mywlan`: external IP lookup and local Wi-Fi device discovery.

## Run

The repository retains the original Windows v0.9 binaries in [release](release). For example, from PowerShell:

```powershell
.\release\secnet-v0.9.exe myip -timeout 10
```

The Perl source is [secnet.pl](secnet.pl). Running from source requires its imported modules, including Net::IP, Net::Ping, Net::DNS::Resolver, LWP::UserAgent, and Data::Validate::URI, plus thread support. Some operations rely on the Windows utilities in [utilities](utilities).

## Reference

See [command options and input formats](docs/commands.md) for IP ranges, files, worker counts, timeouts, and output settings. These are the original implementation and release files; compatibility depends on your Perl and Windows environment.
