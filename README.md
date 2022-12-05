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

## Disclaimer

This tool should not be used as the ultimate source of truth when it comes to
finding out availability or expiry dates of domain names.
Neither authors of this software nor its third-party dependencies bear any
responsibility for possible loss of domain names or other kinds of accidents.
Everyone is highly advised to keep an eye on domain names they own or wish to
obtain using multiple methods.
