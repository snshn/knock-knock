# knock-knock

CLI tool for obtaining and printing domain name information


## How to use

```console
knock-knock \
    github.com \
    gitlab.com
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
