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
    "registration": {
      "status": "registered",
      "expires": "2027-10-09T18:20:50Z",
      "seconds_left": 29981430
    }
  }
]
```

`status` is one of `registered`, `not_registered` or `error` (with `error` containing the reason).
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
