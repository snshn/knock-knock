## What does knock-knock do?

**knock-knock** checks when domain names expire, using the official, standardized registration
data service of domain registries ([RDAP](https://about.rdap.org)), and optionally when their
**TLS certificates** expire too. It also supports **ENS (`.eth`) names**, reading their expiration
straight from Ethereum.

Give it a list of domain names (or URLs) and get back, for each of them:

- 📅 **Expiration date** and days left (negative if already expired)
- 🏢 **Registrar**, its IANA ID and abuse contact
- 🌐 **Name servers** and **DNSSEC** status
- 🔒 **EPP status codes** (e.g. `client transfer prohibited`)
- 🔐 **TLS certificate** expiration, and whether it's trusted (optional)
- ⚠️ A **`needs_attention`** flag for anything expiring soon, untrusted, or failing

## Why use it?

Expired domain names and certificates take websites, email and APIs down, and lapsed domain names
can get picked up by someone else. Run this Actor on a **schedule** (e.g. daily) with your list of
domain names, and connect a **webhook or integration** (Slack, email, Make, Zapier…) to get notified
when something has `needs_attention` set.

## How to use it

1. Enter domain names, one per line: plain names (`example.com`), URLs
   (`https://www.example.co.uk/page`), Gemini URLs (`gemini://example.org`) or ENS names (`vitalik.eth`).
   Subdomains are checked via their registrable domain name (`www.example.co.uk` → `example.co.uk`).
2. Optionally enable **Check TLS certificates**, and adjust **Needs attention within (days)**.
3. Start the Actor and download results as JSON, CSV, Excel, or access them via the API.

## Input example

```json
{
    "domains": ["github.com", "https://www.example.co.uk/", "vitalik.eth"],
    "checkCertificates": true,
    "warnDays": 30
}
```

## Output example

Each checked name produces one item. Besides the summary fields shown in the table, the full details
are included under `registration` and `certificate`:

```json
{
    "input": "github.com",
    "domain": "github.com",
    "naming_system": "dns",
    "registration_status": "registered",
    "expires": "2027-10-09T18:20:50Z",
    "days_left": 347,
    "registrar": "MarkMonitor Inc.",
    "nameservers": ["dns1.p08.nsone.net", "ns-1283.awsdns-32.org"],
    "certificate_expires": "2027-02-05T23:59:59Z",
    "certificate_days_left": 101,
    "certificate_trusted": true,
    "needs_attention": false,
    "error": null,
    "registration": {
        "status": "registered",
        "expires": "2027-10-09T18:20:50Z",
        "seconds_left": 29981430,
        "registered": "2007-10-09T18:20:50Z",
        "statuses": ["client delete prohibited", "client transfer prohibited", "client update prohibited"],
        "dnssec": false,
        "registrar": { "name": "MarkMonitor Inc.", "iana_id": "292", "abuse_email": "abusecomplaints@markmonitor.com" }
    },
    "certificate": {
        "status": "checked",
        "host": "github.com",
        "port": 443,
        "expires": "2027-02-05T23:59:59Z",
        "self_signed": false,
        "trusted": true,
        "verification_error": null
    }
}
```

For ENS names, `registration` also contains `grace_period_ends` (expired ENS names can be renewed
by their owner for 90 more days), and the `owner` and `resolver` addresses.

## FAQ

**Which domain names are supported?**
All top-level domains that offer RDAP, which includes all generic ones (`.com`, `.org`, `.app`…) and
many country-code ones. For the rest, the result contains an error saying no RDAP server is known.

**Is the data reliable?**
It comes straight from registries' official RDAP servers (or from Ethereum for ENS names), not from a
third-party database. Still, keep an eye on important domain names using more than one method.

**Why are some fields empty?**
Registries differ in what they publish, and personal data is usually redacted. Fields that a registry
doesn't provide are `null` (or empty).

**Is it open source?**
Yes, this Actor runs [knock-knock](https://github.com/snshn/knock-knock), an open-source command-line tool,
which you can also use on your own machine.
