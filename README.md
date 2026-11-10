# Webmin ModSecurity Manager

Webmin module for managing Apache + ModSecurity on Ubuntu 24.04 or newer servers
(the common Virtualmin/Webmin stack):

- Apache 2
- `libapache2-mod-security2`
- OWASP Core Rule Set package (`modsecurity-crs`) or local CRS includes

## Features

- **Status**: packages and versions, `security2` state, rule engine mode, CRS paranoia
  level, exclusions, audit log and alerts, with fix-it buttons for common problems
- **Sites**: flagged and blocked requests per Apache virtual host (ServerName and
  ServerAlias from `sites-enabled`), with the top rule and top path for each site
- **Logs**: Serial and JSON audit logs or the Apache error log, optionally including
  rotated logs (`.1`, `.2.gz`, ...)
  - events-over-time chart and top rules, clients, sites and paths; click a bar to filter
  - *Possible false positives*: one rule on one site and path tripped by several
    ordinary clients, with an Exclude button
  - *Likely attackers*: scanners and clients tripping many rules
  - **Export**: the events shown (with the current filters) as CSV, with formula-like
    values defused for Excel; or the raw audit log, rotated copies and optionally the
    Apache error log as a ZIP with a `manifest.txt` of SHA-256 checksums (needs edit
    access, since raw logs can hold passwords and cookies)
- **Exclusion builder**: scope an exclusion to one site, one path and a single request
  field (`ctl:ruleRemoveTargetById`), preview it, then append it with a config test
- **Protection**: `SecRuleEngine` mode, CRS paranoia level and inbound/outbound
  anomaly thresholds (CRS 3 and 4)
- **Alerts**: e-mail and/or Telegram when blocked requests in an interval reach a
  threshold, checked by a cron job in `/etc/cron.d/webmin-modsec-manager`
  - HTML e-mail with a plain-text fallback, sent through the local `sendmail`; preview it
    from the Alerts page without sending
- **Blocked IPs**: block an attacker address in up to three places, with an end time
  (1 hour to 30 days, or until removed) lifted by a cron job
  - **Cloudflare**: an account-level IP Access Rule (block or managed challenge) for every
    proxied site; needs an API token with *Account Firewall Access Rules: Edit*
  - **ModSecurity**: `@ipMatchFromFile` list in `/etc/modsecurity/modsec-ip-blocklist.txt`
    (rule id 1100110), config-tested, then Apache is reloaded
  - **ufw**: deny on all ports; only stops direct connections, not traffic via Cloudflare
  - Cloudflare, private, loopback, this server's and never-block addresses are refused,
    as is the address you use Webmin from
  - *Likely attackers* on the Logs page get a Block button
- **AI bots**: block (403) or only log known AI crawlers by User-Agent, grouped as
  training crawlers (GPTBot, ClaudeBot, CCBot, Bytespider, ...), AI search crawlers and
  user-triggered fetchers (ChatGPT-User, Claude-User, ...)
  - rules live in `/etc/modsecurity/modsec-ai-bots.conf` (ids 1100100-1100109), written
    from the ticked bots, config-tested and rolled back on failure
  - leave chosen sites open, let `/robots.txt` through, and see which bots were caught
- **Cloudflare**: checks the server is ready before attacker IPs are sent to Cloudflare
  - `mod_remoteip` loaded, `RemoteIPHeader CF-Connecting-IP`, and only Cloudflare's
    current ranges (from `api.cloudflare.com`) trusted, so the header cannot be faked
  - recent audit log events carry visitor addresses, not Cloudflare's
  - which sites resolve to Cloudflare (proxied) and which go straight to the server
  - one-click setup writes `conf-available/remoteip-cloudflare.conf`, enables it with
    `a2enmod remoteip` and `a2enconf`, and rolls back if the config test fails
  - Cloudflare real-IP settings already in other files (such as a VirtualHost) are moved
    into that file: the old lines are commented out with a backup, other trusted proxies
    are kept, and a header for a different proxy is never taken over
- Edit `modsecurity.conf`, `security2.conf` and the custom exclusions file
- List, edit, enable and disable rule files (including the CRS `rules/` directory)
- Every change is backed up (last 10 kept), checked with `apachectl configtest`,
  and rolled back automatically if the test fails
- `apt` update / upgrade of the ModSecurity and CRS packages (non-interactive,
  keeps locally changed config files)
- Read-only access: in Webmin Users, set *Can change ModSecurity settings* to No
- **About** page with the module version, builder and release history

## Security

- Changes are only accepted from submitted forms (POST), never from plain links
- Error messages are HTML-escaped; every log field shown in the UI is escaped
- Config text for exclusions is generated server-side from validated fields
- Commands run without a shell; secrets such as the Telegram token never appear on
  the command line, in Webmin action logs or back in the page
- Every config change is backed up, tested with `apachectl configtest` and rolled back
  on failure; backups keep the original file permissions

## Install

On the Webmin server, from this directory:

```sh
sudo ./install.sh
```

The installer copies the module into `/usr/share/webmin/modsec-manager`, creates
`/etc/webmin/modsec-manager/config` (keeping existing settings and adding new ones),
grants the module to the Webmin `root` user and clears the module cache.
Override with `WEBMIN_ROOT`, `WEBMIN_CONFIG` or `WEBMIN_USERS="root admin"`.

Alternatively, install `modsec-manager.wbm.gz` from **Webmin > Webmin Configuration >
Webmin Modules**.

Then open **Servers > ModSecurity Manager**.

## Ubuntu packages

```sh
sudo apt install libapache2-mod-security2 modsecurity-crs
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sudo a2enmod security2
sudo apachectl configtest
sudo systemctl reload apache2
```

## Exclusions

Use the **Exclusion builder** (from Logs, Sites or Exclusions). On Ubuntu, files in `/etc/modsecurity/*.conf` are loaded **before** the CRS rules.
`SecRuleRemoveById` only affects rules that are already loaded, so it does nothing
there. Use runtime exclusions instead:

```apache
SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin-ajax.php" \
    "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
```

## Building

```sh
./build.sh
```

Produces `modsec-manager.wbm.gz` and `webmin-modsec-manager-<version>.tar.gz`.

## Upgrading from 0.1.0

Existing installs keep their `rule_dirs` setting. To manage the CRS rule files, add
`/usr/share/modsecurity-crs/rules` to **Rule/config directories** in Module Config.
