#!/usr/bin/perl
# AI crawlers: block or log known AI bots by User-Agent with a managed rule file.
require './modsec-lib.pl';

&ui_print_header(undef, "AI bots", "");
print_nav('ai_bots.cgi', 'Stop AI crawlers from collecting your sites. Known AI bots are matched by the name in their ' .
    'User-Agent and refused with 403 before any page is served.');

my %s = ai_bot_settings();
my %on = map { $_ => 1 } @{$s{bots}};
my %open = map { $_ => 1 } @{$s{allow}};
my @catalog = ai_bot_catalog();
my $file_ok = -e $s{file};
my $engine = current_engine_mode();
my ($raw, $txs) = read_recent_log('audit');
my $hits = ai_bot_hits($txs);
my $total = 0;
my $blocked = 0;
foreach my $h (values %$hits) { $total += $h->{count}; $blocked += $h->{blocked}; }
my @vhosts = apache_vhosts();

# --- Summary cards ------------------------------------------------------------

my $state = !$s{enabled} ? ['na', 'Off', 'AI crawlers are not checked']
          : !$file_ok ? ['bad', 'File missing', 'Save the settings again to recreate it']
          : $s{mode} eq 'log' ? ['warn', 'Logging only', 'Matches are logged, not blocked']
          : $engine ne 'On' ? ['warn', 'Not blocking', "SecRuleEngine is $engine"]
          : ['ok', 'Blocking', 'Matching requests get 403'];
my @cards = (
    ['AI bot rules', @$state],
    ['Bots selected', @{$s{bots}} ? 'ok' : 'na', scalar(@{$s{bots}}) . " of " . scalar(@catalog), 'Matched by User-Agent'],
    ['Seen in the audit log', $total ? 'ok' : 'na', $total, $total ? "$blocked blocked" : 'No matches in the recent log'],
    ['Sites left open', @{$s{allow}} ? 'warn' : 'ok', scalar(@{$s{allow}}), @{$s{allow}} ? 'AI bots allowed on these sites' : 'Rules apply to every site'],
);
print "<div class='msm-cards'>\n";
foreach my $c (@cards) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]), "</div>",
          "<div class='msm-card-value'>", status_dot($c->[1]), &html_escape($c->[2]), "</div>",
          "<div class='msm-card-sub'>", &html_escape($c->[3]), "</div></div>\n";
}
print "</div>\n";
print_readonly_notice();

if ($s{enabled} && $s{mode} eq 'block' && $engine ne 'On') {
    print callout('warn', "ModSecurity is in <b>" . &html_escape($engine) . "</b> mode, so these rules only log AI crawlers. " .
        "They block once the engine is <b>On</b>.", "<a class='msm-btn' href='mode.cgi'>Change mode</a>");
}

# --- What was caught ----------------------------------------------------------

if ($total) {
    print "<div class='msm-h'>Seen recently</div>\n<div class='msm-wrap'><table class='msm-table'>\n",
          "<tr><th>Bot</th><th>Requests</th><th>Blocked</th><th>Top sites</th><th>Last seen</th></tr>\n";
    foreach my $tok (sort { $hits->{$b}{count} <=> $hits->{$a}{count} } keys %$hits) {
        my $h = $hits->{$tok};
        my @top = sort { $h->{hosts}{$b} <=> $h->{hosts}{$a} } keys %{$h->{hosts}};
        splice(@top, 3) if (@top > 3);
        print "<tr><td><b>", &html_escape($tok), "</b></td><td>$h->{count}</td><td>$h->{blocked}</td><td>",
              &html_escape(join(', ', @top) || '-'), "</td><td>", &html_escape(short_log_time($h->{last}) || '-'),
              "</td></tr>\n";
    }
    print "</table></div>\n";
}

# --- Settings -----------------------------------------------------------------

my $ro = can_edit() ? '' : ' disabled';
sub radio_choice {
    my ($name, $value, $checked, $title, $sub) = @_;
    return "<label class='msm-choice'><input type='radio' name='$name' value='$value'" . ($checked ? " checked" : "") .
           "$ro><span><b>$title</b><small>$sub</small></span></label>";
}

print "<form method='post' action='save_ai_bots.cgi'>";
print "<div class='msm-panel'><div class='msm-panel-title'>Rules</div><div class='msm-panel-sub'>",
      "Written to <span class='msm-path'>", &html_escape($s{file}), "</span> and checked with a config test.</div>\n";
print field_row("AI bot rules",
    "<div class='msm-choices' style='max-width:460px'>" .
    radio_choice('enabled', 1, $s{enabled}, 'On', 'Check every request') .
    radio_choice('enabled', 0, !$s{enabled}, 'Off', 'Remove the rule file') . "</div>");
print field_row("When a bot matches",
    "<div class='msm-choices' style='max-width:460px'>" .
    radio_choice('mode', 'block', $s{mode} eq 'block', 'Block', 'Refuse with 403') .
    radio_choice('mode', 'log', $s{mode} eq 'log', 'Log only', 'See who visits first') . "</div>",
    "Start with <b>Log only</b> for a few days if you are unsure which bots reach your sites.");
print field_row("robots.txt",
    "<label class='msm-inline'><input type='checkbox' name='robots' value='1'" . ($s{robots} ? " checked" : "") .
    "$ro> Let AI bots read <code>/robots.txt</code></label>",
    "Well-behaved crawlers read it first; add <code>Disallow</code> lines there too.");
print "</div>\n";

foreach my $g (ai_bot_groups()) {
    my @bots = grep { $_->{group} eq $g->[0] } @catalog;
    print "<div class='msm-panel'><div class='msm-panel-title'>", &html_escape($g->[1]), "</div>",
          "<div class='msm-panel-sub'>", &html_escape($g->[2]), "</div>\n<div class='msm-choices'>";
    foreach my $b (@bots) {
        my $seen = $hits->{$b->{token}} ? " &middot; seen $hits->{$b->{token}}{count}x" : "";
        print "<label class='msm-choice'><input type='checkbox' name='bot' value='", &html_escape($b->{token}), "'",
              ($on{$b->{token}} ? " checked" : ""), "$ro><span><b>", &html_escape($b->{token}), "</b><small>",
              &html_escape($b->{owner}), "$seen</small></span></label>";
    }
    print "</div></div>\n";
}

if (@vhosts) {
    print "<div class='msm-panel'><div class='msm-panel-title'>Sites left open</div><div class='msm-panel-sub'>",
          "AI bots are allowed on ticked sites (and their aliases). Leave all unticked to protect every site.</div>\n",
          "<div class='msm-choices'>";
    foreach my $v (@vhosts) {
        print "<label class='msm-choice'><input type='checkbox' name='allow' value='", &html_escape($v->{name}), "'",
              ($open{$v->{name}} ? " checked" : ""), "$ro><span><b>", &html_escape($v->{name}), "</b><small>",
              (@{$v->{aliases}} ? &html_escape(join(', ', @{$v->{aliases}})) : 'No aliases'), "</small></span></label>";
    }
    print "</div></div>\n";
}

print "<div class='msm-actions'>", msm_submit("Save and test config", 'primary'), "</div>\n" if (can_edit());
print "</form>\n";

# --- Current rule file --------------------------------------------------------

if ($s{enabled} && @{$s{bots}}) {
    print "<details style='margin-top:16px'><summary>Rule file for these settings</summary><pre>",
          &html_escape(ai_bots_rule_text(\%s, [ site_host_names(@{$s{allow}}) ])), "</pre></details>\n";
}
print "<p class='msm-meta' style='margin-top:14px'>These rules stop bots that announce themselves. Scrapers that pretend ",
      "to be a browser get through; the Core Rule Set still catches scanners by what they do. ",
      "Google-Extended and Applebot-Extended only exist in <code>robots.txt</code>, so they are controlled there. ",
      "For sites behind Cloudflare, its <b>Block AI bots</b> setting does the same at the edge.</p>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
