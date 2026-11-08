#!/usr/bin/perl
# Cloudflare: check that this server is ready to send attacker IPs to
# Cloudflare, and set up real visitor addresses (mod_remoteip) if it is not.
require './modsec-lib.pl';

&ReadParse();
my $action = defined($in{'action'}) ? $in{'action'} : '';
if ($action ne '') {
    require_edit();
    require_post();
}

&ui_print_header(undef, "Cloudflare", "");
print_nav('cloudflare.cgi', $action ? '' :
    "Before attacker IPs can be sent to Cloudflare, ModSecurity must log each visitor's real address, not " .
    "Cloudflare's. These checks show whether this server is ready.");

if ($action eq 'realip') {
    my ($ok, $steps, $msg) = cf_setup_realip();
    print callout($ok ? 'ok' : 'bad', &html_escape($msg));
    &print_command_result(@$_) foreach (@$steps);
    print_reload_form() if ($ok);
    print "<p><a class='msm-btn' href='cloudflare.cgi'>", icon('refresh', 15), "Run the checks again</a></p>\n";
    print_page_end();
    &ui_print_footer("cloudflare.cgi", "Cloudflare checks");
    exit;
} elsif ($action ne '') {
    fail("Unknown action");
}

my %r = cloudflare_readiness(live => 1, dns => 1);
my @checks = @{$r{checks}};
my $passed = grep { $_->{state} eq 'ok' } @checks;
my $counted = grep { $_->{state} ne 'na' } @checks;
my @sites = @{$r{sites}};
my $proxied = grep { $_->{state} eq 'proxied' || $_->{state} eq 'mixed' } @sites;

# --- Summary cards ------------------------------------------------------------

my $verdict = $r{ready} ? ['ok', 'Ready', 'Attacker IPs can be blocked at Cloudflare']
            : @{$r{blocking}} ? ['bad', 'Not ready', scalar(@{$r{blocking}}) . ' problem' . (@{$r{blocking}} > 1 ? 's' : '') . ' to fix first']
            : ['warn', 'Almost ready', (grep { $_->{id} eq 'log' && $_->{state} eq 'na' } @checks)
                ? 'Waiting for ModSecurity to log a request' : 'See the items marked below'];
my %src = (live => 'Live from api.cloudflare.com', saved => 'Saved copy (API not reachable)',
           'built-in' => 'Built-in list (API not reachable)');
my @cards = (
    ['Cloudflare blocking', @$verdict],
    ['Checks passed', $counted && $passed == $counted ? 'ok' : 'warn', "$passed of $counted", 'Items that do not apply yet are not counted'],
    ['Sites on Cloudflare', !@sites ? 'na' : $proxied ? 'ok' : 'warn', @sites ? "$proxied of " . scalar(@sites) : 'None found',
        'Sites whose DNS points at Cloudflare'],
    ['Cloudflare ranges', $r{range_source} eq 'live' ? 'ok' : 'warn', scalar(@{$r{ranges}}), $src{$r{range_source}}],
);
print "<div class='msm-cards'>\n";
foreach my $c (@cards) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]), "</div>",
          "<div class='msm-card-value'>", status_dot($c->[1]), &html_escape($c->[2]), "</div>",
          "<div class='msm-card-sub'>", &html_escape($c->[3]), "</div></div>\n";
}
print "</div>\n";
print_readonly_notice();

# --- Requirements -------------------------------------------------------------

my $mig = $r{migration};
my $fix_label = $mig->{ok} ? 'Move and set up real visitor IPs'
              : $r{managed} ? 'Update real-IP settings' : 'Set up real visitor IPs';
my $fix_shown = 0;
print "<div class='msm-panel'><div class='msm-panel-title'>Requirements</div><div class='msm-panel-sub'>",
      "Red items must be fixed before attacker IPs are sent to Cloudflare.</div>\n";
foreach my $c (@checks) {
    my $side = '';
    if ($c->{fix} && can_edit() && !$fix_shown++) {
        $side = "<form method='post' action='cloudflare.cgi' style='margin:0'>" . &ui_hidden('action', $c->{fix}) .
                msm_submit($fix_label, 'primary') . "</form>";
    }
    print "<div class='msm-ins'><div class='msm-ins-main'>", status_dot($c->{state}), "<b>", &html_escape($c->{title}),
          "</b><div class='msm-ins-sub'>", $c->{detail}, "</div></div>",
          ($side ? "<div class='msm-ins-side'>$side</div>" : ""), "</div>\n";
}
print "</div>\n";

if ($fix_shown && $mig->{ok}) {
    my %by;
    push(@{$by{$_->{file}}}, $_->{line}) foreach (@{$mig->{edits}});
    print callout('info', "Real-IP settings were found in files this module does not manage. <b>$fix_label</b> moves them " .
        "into one setting for every site:<ul style='margin:6px 0'>" .
        join('', map { "<li><span class='msm-path'>" . &html_escape($_) . "</span>, lines " .
                       &html_escape(join(', ', @{$by{$_}})) . " are commented out (a backup is kept)</li>" } sort keys %by) .
        "<li><span class='msm-path'>" . &html_escape(cf_realip_conf_file()) . "</span> gets <code>RemoteIPHeader " .
        "CF-Connecting-IP</code> and all " . scalar(@{$r{ranges}}) . " Cloudflare ranges" .
        (@{$mig->{carry}} ? ", plus the other trusted proxies found there: <code>" .
            &html_escape(join(', ', map { (split(/\s+/, $_, 2))[1] } @{$mig->{carry}})) . "</code>" : "") . "</li>" .
        (@{$mig->{dropped}} ? "<li>Dropped because they trust almost every address: <code>" .
            &html_escape(join(', ', @{$mig->{dropped}})) . "</code></li>" : "") .
        "</ul>Then <code>remoteip</code> and the snippet are enabled and the config is tested. Everything is undone if the test fails.");
} elsif ($fix_shown) {
    print callout('info', "<b>$fix_label</b> writes <span class='msm-path'>" . &html_escape(cf_realip_conf_file()) .
        "</span> with <code>RemoteIPHeader CF-Connecting-IP</code> and every Cloudflare range as a trusted proxy, " .
        "enables <code>remoteip</code> and the snippet, and runs a config test. Everything is undone if the test fails.");
} elsif (@{$r{foreign_headers}} && grep { $_->{state} ne 'ok' && $_->{id} =~ /^(?:header|trusted)$/ } @checks) {
    my $f = $r{foreign_headers}[0];
    print callout('warn', $mig->{reason} ? &html_escape($mig->{reason}) :
        "The real-IP settings come from <span class='msm-path'>" . &html_escape("$f->{file}:$f->{line}") .
        "</span>, which this module does not manage. Fix it there (Config page or by hand) so two settings do not conflict.");
}

print "<p class='msm-meta'>Once this server is ready, block attackers and add the Cloudflare API token on the <a href='blocks.cgi'>Blocked IPs</a> page.</p>\n";

# --- Sites --------------------------------------------------------------------

if (@sites) {
    my %label = (proxied => ['ok', 'Proxied'], mixed => ['warn', 'Partly proxied'],
                 direct => ['na', 'DNS only'], none => ['na', 'Does not resolve']);
    print "<div class='msm-h'>Sites</div>\n<div class='msm-wrap'><table class='msm-table'>\n",
          "<tr><th>Site</th><th>Resolves to</th><th>Cloudflare</th></tr>\n";
    foreach my $s (@sites) {
        my $l = $label{$s->{state}};
        print "<tr><td><b>", &html_escape($s->{name}), "</b></td><td><span class='msm-path'>",
              &html_escape(join(', ', @{$s->{ips}}) || '-'), "</span></td><td>", status_dot($l->[0]),
              &html_escape($l->[1]), "</td></tr>\n";
    }
    print "</table></div>\n";
    print "<p class='msm-meta'>Only proxied (orange cloud) sites are protected by a block at Cloudflare. ",
          "Sites on DNS only reach this server directly.</p>\n";
}

# --- Details ------------------------------------------------------------------

my @dirs = @{$r{directives}};
print "<div class='msm-panel'><div class='msm-panel-title'>Details</div><div class='msm-panel-sub'>",
      "What the checks above are based on.</div>\n";
print "<details><summary>mod_remoteip settings found (", scalar(@dirs), ")</summary>";
if (@dirs) {
    print "<div class='msm-wrap'><table class='msm-table'><tr><th>File</th><th>Directive</th></tr>\n";
    foreach my $d (@dirs) {
        print "<tr><td><span class='msm-path'>", &html_escape("$d->{file}:$d->{line}"), "</span>",
              ($d->{vhost} ? " <span class='msm-badge'>VirtualHost</span>" : ""), "</td><td><code>",
              &html_escape(substr($d->{args}, 0, 200)), "</code> <span class='msm-meta'>",
              &html_escape($d->{directive}), "</span></td></tr>\n";
    }
    print "</table></div>";
} else {
    print "<p class='msm-meta'>None in the enabled Apache configuration.</p>";
}
print "</details>\n";
print "<details><summary>Cloudflare address ranges (", scalar(@{$r{ranges}}), ", ", &html_escape($src{$r{range_source}}),
      ")</summary><pre>", &html_escape(join("\n", @{$r{ranges}})), "</pre></details>\n";
print "</div>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
