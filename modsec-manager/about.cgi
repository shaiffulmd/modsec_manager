#!/usr/bin/perl
# About: version, builder, environment and release history.
require './modsec-lib.pl';

&ui_print_header(undef, "About", "");
print_nav('about.cgi');

my %m = module_meta();
my $webmin = defined(&get_webmin_version) ? &get_webmin_version() : '';
my $host = defined(&get_system_hostname) ? &get_system_hostname() : '';
my $mv = package_version('libapache2-mod-security2');
my $cv = package_version('modsecurity-crs');

print "<div class='msm-hero'><span class='msm-logo'>", icon('shield', 36), "</span><div>",
      "<h2>ModSecurity Manager</h2>",
      "<p>A Webmin module for running the ModSecurity web application firewall and the OWASP Core Rule Set ",
      "on Apache: see what is being blocked, tune out false positives safely and get alerted when attacks spike.</p>",
      "<div class='msm-hero-meta'><span class='msm-pill'>", icon('tag', 14), "&nbsp;Version ", &html_escape($m{version}),
      "</span><span class='msm-pill'>", icon('user', 14), "&nbsp;Built by ", &html_escape($m{author}), "</span></div>",
      "</div></div>\n";

print "<div class='msm-cards'>\n";
foreach my $c (['Module version', $m{version}, 'modsec-manager'],
               ['Built by', $m{author}, 'Author and maintainer'],
               ['ModSecurity', $mv || 'Not installed', 'libapache2-mod-security2'],
               ['OWASP CRS', $cv || 'Not installed', 'modsecurity-crs'],
               ['Webmin', $webmin || '-', $host]) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]),
          "</div><div class='msm-card-value' style='font-size:18px'>", &html_escape($c->[1]),
          "</div><div class='msm-card-sub'>", &html_escape($c->[2]), "</div></div>\n";
}
print "</div>\n";

my @features = (
    ['gauge',    'Status at a glance',  'Engine mode, packages, CRS level and fix-it buttons for common problems.'],
    ['globe',    'Per-site view',       'Flagged and blocked requests for every Apache virtual host.'],
    ['activity', 'Log insights',        'Charts, likely false positives and likely attackers from the audit log.'],
    ['wand',     'Exclusion builder',   'Exclude a rule for one site, path or request field, with a config test.'],
    ['sliders',  'Protection tuning',   'SecRuleEngine mode, paranoia level and anomaly thresholds.'],
    ['bell',     'Alerts',              'E-mail or Telegram when blocked requests spike.'],
    ['bot',      'AI bot blocking',     'Block or log GPTBot, ClaudeBot, CCBot and other AI crawlers, per site.'],
    ['cloud',    'Cloudflare readiness', 'Checks real visitor IPs behind Cloudflare and sets up mod_remoteip safely.'],
    ['shield',   'Safe changes',        'Every change is backed up, tested with apachectl and rolled back on failure.'],
    ['user',     'Access control',      'Give Webmin users read-only access to the module.'],
);
print "<div class='msm-grid2'>\n<div class='msm-panel'><div class='msm-panel-title'>What it does</div><div class='msm-panel-sub'>&nbsp;</div>",
      "<div class='msm-grid3' style='grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr))'>";
foreach my $f (@features) {
    print "<div class='msm-feature'><span class='msm-tile-ico'>", icon($f->[0], 18), "</span><span><b>",
          &html_escape($f->[1]), "</b><span>", &html_escape($f->[2]), "</span></span></div>";
}
print "</div></div>\n";

my @releases = (
    ['0.7.1', 'Cloudflare setup can now move real-IP settings out of VirtualHost blocks (as Virtualmin sites often have) into one setting for every site: the old lines are commented out with a backup, non-Cloudflare trusted proxies are kept, ranges that trust everyone are dropped, and all of it is undone if the config test fails.'],
    ['0.7.0', 'New AI bots page: block or log known AI crawlers (training, AI search and user-triggered fetchers) by User-Agent with a managed ModSecurity rule file, leave chosen sites open, let robots.txt through, and see which bots were caught.'],
    ['0.6.0', 'New Cloudflare page: checks that mod_remoteip logs real visitor addresses (CF-Connecting-IP, trusted Cloudflare ranges, audit log, site DNS) before attacker IPs are sent to Cloudflare, with a one-click real-IP setup that is rolled back if the config test fails.'],
    ['0.5.2', 'Redesigned Sites page: summary cards, site search, card rows for active sites with alias chips, and quiet sites folded away. Table spacing now holds against themes that force cell padding.'],
    ['0.5.1', 'The Alerts page buttons (save, send test, preview) now sit in one row.'],
    ['0.5.0', 'Professional HTML alert e-mails with a plain-text fallback, an e-mail preview on the Alerts page, and a setting for the Webmin address used in alert links.'],
    ['0.4.1', 'Interface fixes: table cells keep their spacing under every Webmin theme, card icons are centred, and code snippets use neutral colours.'],
    ['0.4.0', 'Security hardening (escaped errors, form-only changes, secrets kept off the command line), a redesigned interface and this About page.'],
    ['0.3.0', 'Sites page, exclusion builder, false-positive and attacker insights, CRS tuning, e-mail/Telegram alerts and rotated logs.'],
    ['0.2.0', 'Log charts and filters, a new status page, safer file writes, read-only access and a fixed installer.'],
    ['0.1.0', 'First release: engine mode, exclusions file, config test and reload, audit log view.'],
);
print "<div class='msm-panel'><div class='msm-panel-title'>Release history</div><div class='msm-panel-sub'>&nbsp;</div><ul class='msm-timeline'>";
foreach my $r (@releases) {
    print "<li><b>Version ", &html_escape($r->[0]), ($r->[0] eq $m{version} ? " <span class='msm-badge'>current</span>" : ""),
          "</b><span>", &html_escape($r->[1]), "</span></li>";
}
print "</ul></div>\n</div>\n";

print "<p class='msm-meta'>ModSecurity and the OWASP Core Rule Set are separate open-source projects. ",
      "This module manages them and is not affiliated with their maintainers.</p>\n";

print_page_end();
&ui_print_footer("", $text{'index_return'});
