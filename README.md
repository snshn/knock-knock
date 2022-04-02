# knock-knock

CLI tool for obtaining and outputting domain name information in an easy-to-read format.


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

```console
knock-knock -f crates.io
```
```
crates.io:
    Domain name will expire in 294 days, 8 hours, 57 minutes, 11 seconds
```
