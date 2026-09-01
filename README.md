# upsw
A small, self-contained Bash script that generates a Postfix Postscreen CIDR allowlist for major email providers.

The script resolves the published SPF records of selected providers and converts their outbound mail networks into a Postscreen-compatible CIDR map.

Yahoo is handled separately because its published SPF record uses `ptr:` mechanisms and does not expose all of its outbound networks as `ip4:`/`ip6:` mechanisms. For Yahoo, the script retrieves the official outbound mail server list published by Yahoo.

## Why?

Postscreen's SMTP protocol tests are useful for rejecting poorly behaved SMTP clients before they reach Postfix `smtpd`.

However, some large email providers operate large outbound SMTP pools and may retry a temporarily deferred message from a different IP address.

This can interact poorly with Postscreen's after-220 tests, because a new client may need to reconnect from the same IP before Postscreen considers it an established client.

A practical solution is to allow known outbound networks belonging to trusted large mail providers to bypass Postscreen testing while keeping the tests enabled for other SMTP clients.

This script automates maintenance of such an allowlist.

## Supported providers

Currently:

* Google
* Microsoft 365 / Outlook
* Apple iCloud Mail
* Amazon SES
* Yahoo

Google, Microsoft, Apple and Amazon SES are resolved from their published SPF records.

Yahoo is resolved from Yahoo's official outbound mail server list.

## Features

* Self-contained Bash implementation
* No external SPF parsing library required
* Recursive SPF `include:` resolution
* SPF `redirect=` support
* IPv4 and IPv6 SPF networks
* Loop protection while resolving SPF records
* Yahoo outbound network retrieval from Yahoo's official published list
* IPv4 validation for data extracted from Yahoo
* Invalid Yahoo addresses are reported and skipped instead of aborting the update
* Sanity check on the number of Yahoo networks retrieved
* Atomic replacement of the Postscreen allowlist
* Postfix is reloaded only when the generated list changes
* `flock` prevents concurrent executions
* Existing allowlist is preserved if a provider cannot be resolved correctly

## Requirements

The script requires:

* Bash
* `dig`
* `curl`
* `flock`
* Postfix

On Debian/Ubuntu systems the required utilities are normally provided by packages such as:

```bash
apt install dnsutils curl util-linux
```

Postfix must of course already be installed and configured.

## Installation

Copy the script somewhere suitable, for example:

```bash
install -m 755 update_postscreen_whitelist.sh \
    /usr/local/sbin/update_postscreen_whitelist
```

Run it as root:

```bash
/usr/local/sbin/update_postscreen_whitelist
```

The generated allowlist is written to:

```text
/etc/postfix/postscreen_whitelist.cidr
```

## Postfix configuration

Configure Postscreen to consult the generated CIDR map.

For example:

```text
postscreen_access_list =
    permit_mynetworks,
    cidr:/etc/postfix/postscreen_whitelist.cidr
```

The equivalent `postconf` command is:

```bash
postconf -e \
    'postscreen_access_list = permit_mynetworks, cidr:/etc/postfix/postscreen_whitelist.cidr'
```

Reload Postfix after changing the Postscreen configuration:

```bash
systemctl reload postfix
```

The update script itself reloads Postfix automatically whenever the generated allowlist changes.

## Testing

You can test whether an address matches the generated CIDR map with:

```bash
postmap -q 77.238.179.82 \
    cidr:/etc/postfix/postscreen_whitelist.cidr
```

A matching address should return:

```text
permit
```

An address that does not match returns no output.

## Yahoo handling

Yahoo requires special handling.

At the time this project was written, Yahoo's SPF record contains mechanisms such as:

```text
ptr:yahoo.com
ptr:yahoo.net
```

A `ptr:` SPF mechanism cannot be usefully flattened into a static list of CIDR networks.

Instead, Yahoo publishes an official list of its outbound mail servers:

https://senders.yahooinc.com/outbound-mail-servers/

The script downloads this page and extracts candidate IPv4 addresses and CIDR networks.

Because arbitrary HTML can contain strings that resemble IPv4 addresses, candidates are validated before they are added to the Postscreen map.

For example, a string such as:

```text
933.002.657.657
```

matches a simple IPv4-shaped regular expression but is not a valid IPv4 address.

The script therefore validates every octet and reports invalid candidates:

```text
WARNING: ignoring invalid Yahoo IPv4 address: 933.002.657.657
```

Individual invalid entries do **not** abort the update.

However, if fewer than a minimum number of valid Yahoo entries are obtained, the update is aborted. This protects the existing allowlist against major changes to Yahoo's page structure or a broken download/parser.

## SPF resolution

SPF records may reference other SPF records recursively.

For example:

```text
v=spf1 include:_example.example.net -all
```

The script follows `include:` mechanisms recursively.

It also supports SPF `redirect=` modifiers. This is required by providers such as Apple, whose public domains may redirect SPF evaluation to another SPF record.

Already visited SPF domains are tracked to avoid resolution loops.

The script extracts:

```text
ip4:
ip6:
include:
redirect=
```

Other SPF mechanisms are intentionally ignored.

This script is **not a general-purpose SPF evaluator**. It only extracts network information needed to construct a static Postscreen allowlist.

## Automatic updates

Provider mail networks can change, so the script should be executed periodically.

For example, using cron:

```text
17 4 * * * root /usr/local/sbin/update_postscreen_whitelist
```

Running once per day is normally sufficient for this use case.

The script compares the newly generated list with the currently installed one. If they are identical, Postfix is not reloaded.

## Failure behavior

The script deliberately follows a conservative update policy.

If a critical provider source cannot be retrieved or produces no usable networks, the script exits without replacing the existing allowlist.

Invalid individual Yahoo candidates are an exception: they are reported and ignored while processing continues.

This means a transient DNS, HTTP or parser failure should not replace a working allowlist with an incomplete one.

## Security considerations

Entries in `postscreen_access_list` marked `permit` bypass Postscreen tests.

Therefore, adding a provider to this script is a security decision.

Large shared outbound services such as Amazon SES can be used by many independent senders. Allowlisting such a provider means trusting its outbound infrastructure sufficiently to bypass Postscreen, not necessarily trusting every message sent through that infrastructure.

Review the provider list and remove any providers that you do not want to bypass Postscreen on your server.

This script does not replace:

* SMTP authentication
* SPF verification
* DKIM verification
* DMARC
* content filtering
* spam filtering
* malware scanning

It only maintains a Postscreen access list.

## Related projects

[postwhite](https://github.com/stevejenkins/postwhite) is a mature and substantially more comprehensive Postscreen whitelist/blacklist generator supporting many providers and additional functionality.

This project is an independent and deliberately smaller implementation. It focuses on a small set of major providers, performs SPF traversal directly without requiring an external SPF parsing toolkit, and handles Yahoo's published outbound server list internally.

If you need a much broader provider database or more advanced whitelist/blacklist management, postwhite is worth considering.

## License

Choose a license before publishing the repository.

The MIT License is a good option for a small administrative utility intended to be freely reused and modified.

## Disclaimer

This software modifies a Postfix Postscreen allowlist and may therefore affect how SMTP connections are filtered.

Review the generated networks and configuration before deploying it on a production mail server.

Use at your own risk.
