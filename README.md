# knock-knock

CLI tool for obtaining and printing domain name information


## Installation

#### Using [Cargo](https://crates.io/crates/knock-knock) (cross-platform)

```console
cargo install knock-knock
```

#### From [source](https://github.com/snshn/knock-knock)

```console
git clone https://github.com/snshn/knock-knock.git
cd knock-knock
make install
```


## Usage

```console
knock-knock github.com gitlab.com
```
```
github.com:
    Domain name will expire in 189 days
gitlab.com:
    Domain name will expire in 1018 days
```
or

```console
knock-knock -f crates.io
```
```
crates.io:
    Domain name will expire in 294 days, 8 hours, 57 minutes, 11 seconds
```

URLs and internationalized domain names are accepted too:

```console
knock-knock https://www.rust-lang.org/learn bücher.de
```

ENS (`.eth`) names are supported too, their expiration info is read directly from
Ethereum (ENS's .eth registrar contract) via a JSON-RPC endpoint:

```console
knock-knock vitalik.eth
```
```
vitalik.eth:
    ENS name will expire in 2918 days
```

Once expired, ENS names have a 90-day grace period during which only their owner can renew them,
knock-knock shows how much of it is left.

By default `https://ethereum-rpc.publicnode.com` is used, a different endpoint
(e.g. your own node) can be set with `--eth-rpc-url` or the `ETH_RPC_URL` environment variable.
Keep in mind that the endpoint gets to see which names are being looked up.

TLS certificates can be checked as well, using `-c`:

```console
knock-knock -c github.com https://example.com:8443/
```
```
github.com:
    Domain name will expire in 347 days
    TLS certificate will expire in 61 days
example.com:
    Domain name will expire in 291 days
    TLS certificate (port 8443) will expire in 12 days
    TLS certificate (port 8443) is not trusted: issued by an unknown certificate authority
```

Gemini capsules are supported too (port 1965 by default); since Gemini relies on
trust on first use, self-signed certificates are not reported as untrusted for them:

```console
knock-knock -c gemini://geminiprotocol.net
```
```
geminiprotocol.net:
    Domain name will expire in 207 days
    TLS certificate (Gemini) will expire in 1503 days
```

Certificates are verified against the operating system's trust store,
but information is shown even for expired, self-signed or otherwise untrusted ones.

Results can also be output in JSON format, e.g. for use in scripts:

```console
knock-knock --json github.com
```
```json
[
  {
    "input": "github.com",
    "host": "github.com",
    "domain": "github.com",
    "scheme": null,
    "naming_system": "dns",
    "registration": {
      "status": "registered",
      "expires": "2027-10-09T18:20:50Z",
      "seconds_left": 29981430,
      "registered": "2007-10-09T18:20:50Z",
      "last_changed": "2025-09-07T09:18:27Z",
      "statuses": [
        "client delete prohibited",
        "client transfer prohibited",
        "client update prohibited"
      ],
      "nameservers": [
        "dns1.p08.nsone.net",
        "dns2.p08.nsone.net",
        "ns-1283.awsdns-32.org",
        "ns-1707.awsdns-21.co.uk"
      ],
      "dnssec": false,
      "registrar": {
        "name": "MarkMonitor Inc.",
        "iana_id": "292",
        "abuse_email": "abusecomplaints@markmonitor.com",
        "abuse_phone": "+1.2086851750"
      },
      "whois_server": null
    }
  }
]
```

`status` is one of `registered`, `not_registered` or `error` (with `error` containing the reason).
For registered names, whatever else the registry provides is included as well (registration date,
[EPP status codes](https://icann.org/epp), name servers, DNSSEC, registrar and its abuse contact);
fields are `null` (or empty) when the registry doesn't provide them.
For ENS names, the owner's address (looking through ENS's NameWrapper for wrapped names)
and the resolver contract's address are included as `owner` and `resolver`.
With `-c`, each object also has a `certificate` member (`status` being `checked`, `not_applicable` or `error`),
containing `host`, `port`, `not_before`, `expires`, `seconds_left`, `self_signed`, `trusted` and `verification_error`.

Domain names are checked concurrently, but results are always printed
in the order they were given.

Expiration info is shown in green, in yellow when the domain name expires
within 4 weeks, and in red when it expires within a week (or has already expired).
Colors are disabled when output is not a terminal, or when the
[`NO_COLOR`](https://no-color.org) environment variable is set.

#### Exit status

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| `0`  | All domain names were checked successfully                           |
| `1`  | Information for at least one domain name could not be obtained       |

## Disclaimer

This tool should not be used as the ultimate source of truth when it comes to
finding out availability or expiry dates of domain names.
Neither authors of this software nor its third-party dependencies bear any
responsibility for possible loss of domain names or other kinds of accidents.
Everyone is highly advised to keep an eye on domain names they own or wish to
obtain using multiple methods.
