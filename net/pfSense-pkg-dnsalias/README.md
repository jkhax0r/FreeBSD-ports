# DNS Alias

DNS Alias 0.2.42 targets pfSense 2.9.0, Unbound 1.26.1, FreeBSD 16 amd64
and CPython 3.11. The checked-in source includes the five C extensions.
The firewall-table helper indexes exact names and wildcard suffixes for larger
alias sets. CNAME targets must preserve their DNS label boundaries.

## Build

In a disposable build environment for the corresponding pfSense development
branch, run `make package` and `make test` in this directory. The port compiles
the C extensions and creates their identity records as part of the build.
The package owns nine staged files. Its install and removal scripts track
the separate runtime, configuration and WebGUI files created on the appliance.

## Use

Open **Firewall > DNS Aliases**. Save exact names or wildcard subdomains.
For example, add both `example.com` and `*.example.com` to include the apex
and its subdomains. Enable the service in DNS Alias settings. Choose its
`da_<name>` destination in an ordinary firewall rule and select the interface,
source, ports and action there. Fresh installation starts disabled and creates
no firewall rules. The package works with plain Unbound. pfBlockerNG integration
is optional.

Each trusted answer contributes an address until its remaining DNS TTL expires.
Multiple names and clients can contribute to the same destination table.
Stopping the service empties its tables. Rule order determines what then
happens to new traffic. Shared CDN addresses can match several domains.

## Qualification

Resolver reload, native upgrade and removal were tested with the original
package. Reboot recovery testing is pending.
The ports recipe still needs a clean build and Package Manager installation,
upgrade and removal on the target development version. The public maintainer
and redistribution license are pending.
