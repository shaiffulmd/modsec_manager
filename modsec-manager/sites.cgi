#!/usr/bin/perl
# Per-site view: which Apache virtual hosts ModSecurity flags most.
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Sites", "");
print_nav('sites.cgi', 'Which websites on this server ModSecurity flags most, matched by ServerName and ServerAlias.');

my %p = paths();
my $history = ($in{'history'} || 0) =~ /^([0-7])$/ ? $1 : 0;
my $q = defined($in{'q'}) ? $in{'q'} : '';
$q =~ s/^\s+|\s+$//g;
my ($raw, $txs, $file, $err) = read_recent_log('audit', $history);
my @vh = apache_vhosts();

# Group events by site.
my (%s, %unmatched);
foreach my $tx (@$txs) {
    my $site = site_for_host($tx->{host}, \@vh);
    $unmatched{norm_host($tx->{host}) || '(no Host header)'}++ if (!$site);
    my $e = $s{$site} ||= { events => 0, blocked => 0, txs => [], last => '' };
    $e->{events}++;
    $e->{blocked}++ if tx_blocked($tx);
    push(@{$e->{txs}}, $tx);
    $e->{last} ||= $tx->{time};   # $txs is newest first
}

my $match = sub {
    my ($v) = @_;
    return 1 if ($q eq '');
    return scalar(grep { index($_, lc($q)) >= 0 } ($v->{name}, @{$v->{aliases}}));
};
my @active = sort { $s{$b->{name}}{events} <=> $s{$a->{name}}{events} || $a->{name} cmp $b->{name} }
             grep { $s{$_->{name}} && $match->($_) } @vh;
my @quiet = sort { $a->{name} cmp $b->{name} } grep { !$s{$_->{name}} && $match->($_) } @vh;
my $other = $q eq '' ? $s{''} : undef;   # "Other hosts" only without a search

# --- Summary ----------------------------------------------------------------

my $total = scalar(@$txs);
my $blocked = grep { tx_blocked($_) } @$txs;
my $with_activity = grep { $s{$_->{name}} } @vh;
print "<div class='msm-cards'>\n";
foreach my $c (['Websites', scalar(@vh), 'Virtual hosts in sites-enabled'],
               ['With activity', $with_activity, scalar(@vh) - $with_activity . ' quiet'],
               ['Flagged requests', $total, $history ? 'Including rotated logs' : 'In the current log window'],
               ['Blocked', $blocked, $total ? sprintf("%d%% of flagged", 100 * $blocked / $total + 0.5) : 'None']) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]),
          "</div><div class='msm-card-value'>", &html_escape($c->[1]),
          "</div><div class='msm-card-sub'>", &html_escape($c->[2]), "</div></div>\n";
}
print "</div>\n";

print "<form method='get' action='sites.cgi' class='msm-filters'>",
      "<input name='q' value='", &html_escape($q), "' placeholder='Find a site' size='24'>",
      history_select($file, $history), &ui_submit("Show"),
      ($q ne '' ? " <a href='sites.cgi" . ($history ? "?history=$history" : "") . "'>Clear</a>" : ""), "</form>\n";
print callout('info', &html_escape($err)) if ($err);
if (!@vh) {
    print callout('warn', "No virtual hosts were found in <span class='msm-path'>" . &html_escape($p{apache_sites_dir}) .
                          "</span>. Set the sites directory in Module Config.");
}

# --- Active sites -----------------------------------------------------------

my $max = 1;
foreach my $e (values %s) { $max = $e->{events} if ($e->{events} > $max); }

# Aliases as short chips: "www.shop.example.com" -> "www" when under the
# site's own name; anything else is shown in full.
sub alias_chips {
    my ($v) = @_;
    my @a = @{$v->{aliases}};
    return '' if (!@a);
    my @short = map { my $x = $_; $x =~ s/\.\Q$v->{name}\E$// ? $x : $x } @a;
    my @show = @short > 5 ? @short[0 .. 4] : @short;
    return "<span class='msm-site-chips' title='" . &html_escape(join(', ', @a)) . "'>" .
           join('', map { "<span class='msm-chip-sm'>" . &html_escape($_) . "</span>" } @show) .
           (@short > 5 ? "<span class='msm-chip-sm'>+" . (@short - 5) . "</span>" : "") . "</span>";
}

sub site_row {
    my ($name, $meta, $e, $logs_href, $site_host, $dot) = @_;
    my $n = $e->{events};
    my $logged = $n - $e->{blocked};
    my ($top_rule) = grep { !is_score_rule($_->[0]) } top_values($e->{txs}, \&tx_rule_ids);
    my ($top_path) = top_values($e->{txs}, \&tx_path, 1);
    my $pct = $n ? int(100 * $e->{blocked} / $n + 0.5) : 0;
    my $h = "<div class='msm-site'>";
    $h .= "<div class='msm-site-main'><div class='msm-site-name'>" . status_dot($dot || ($e->{blocked} ? 'bad' : 'warn')) .
          "<span>" . &html_escape($name) . "</span></div>" . ($meta ? "<div class='msm-site-meta'>$meta</div>" : "") . "</div>";
    $h .= "<div class='msm-site-stat'><div class='msm-site-nums'><b>$n</b> flagged <span class='msm-sep'>&middot;</span> " .
          "<b>$e->{blocked}</b> blocked <span class='msm-meta'>$pct%</span></div>" .
          "<div class='msm-hbar-track'>" .
          ($e->{blocked} ? "<span style='width:" . (100 * $e->{blocked} / $max) . "%;background:var(--s2)'></span>" : "") .
          ($logged ? "<span style='width:" . (100 * $logged / $max) . "%;background:var(--s1)'></span>" : "") .
          "</div></div>";
    $h .= "<div class='msm-site-top'>" .
          "<div><span class='msm-site-k'>Top rule</span>" .
          ($top_rule ? "<b>" . &html_escape($top_rule->[0]) . "</b> <span class='msm-meta'>&times;$top_rule->[1]</span>" : "<span class='msm-meta'>&ndash;</span>") .
          "</div><div><span class='msm-site-k'>Top path</span>" .
          ($top_path ? "<span class='msm-path'>" . &html_escape($top_path->[0]) . "</span> <span class='msm-meta'>&times;$top_path->[1]</span>" : "<span class='msm-meta'>&ndash;</span>") .
          "</div><div><span class='msm-site-k'>Last</span><span class='msm-meta'>" . &html_escape(short_log_time($e->{last})) . "</span></div></div>";
    $h .= "<div class='msm-site-actions'><a class='msm-btn msm-btn-sm' href='$logs_href'>" . icon('activity', 14) . "Logs</a>";
    if ($top_rule && can_edit()) {
        $h .= "<a class='msm-btn msm-btn-sm' href='exclusion_builder.cgi?rule=" . &url_escape($top_rule->[0]) .
              ($site_host ? "&amp;host=" . &url_escape($site_host) : "") . ($history ? "&amp;history=$history" : "") .
              "' title='Build an exclusion for rule " . &html_escape($top_rule->[0]) . " on this site'>" . icon('wand', 14) . "Exclude</a>";
    }
    return $h . "</div></div>\n";
}

if (@active || $other) {
    print "<div class='msm-legend' style='margin-top:4px'><span><span class='msm-sw' style='background:var(--s2)'></span>Blocked</span>",
          "<span><span class='msm-sw' style='background:var(--s1)'></span>Logged only</span></div>\n";
    print "<div class='msm-list'>\n";
    foreach my $v (@active) {
        my $meta = alias_chips($v);
        $meta .= "<span class='msm-site-ports'>" . &html_escape(join(' / ', @{$v->{ports}})) . "</span>" if (@{$v->{ports}});
        print site_row($v->{name}, $meta, $s{$v->{name}},
                       "logs.cgi?site=" . &url_escape($v->{name}) . ($history ? "&amp;history=$history" : ""), $v->{name});
    }
    if ($other) {
        my @h = sort { $unmatched{$b} <=> $unmatched{$a} } keys %unmatched;
        my $list = join('', map { "<span class='msm-chip-sm'>" . &html_escape($_) . " &times;$unmatched{$_}</span>" }
                             @h[0 .. ($#h < 4 ? $#h : 4)]);
        print site_row("Other hosts", "<span class='msm-site-chips'>$list</span><span class='msm-site-ports'>No matching virtual host</span>",
                       $other, "logs.cgi" . ($history ? "?history=$history" : ""), '', 'na');
    }
    print "</div>\n";
} elsif (@vh) {
    print callout('ok', $q ne '' ? "No site matching <b>" . &html_escape($q) . "</b> was flagged in this window."
                                 : "No site was flagged in this log window.");
}

# --- Quiet sites ------------------------------------------------------------

if (@quiet) {
    print "<details class='msm-panel msm-quiet'", (@active ? "" : " open"), "><summary>",
          scalar(@quiet), " quiet site", (@quiet == 1 ? "" : "s"),
          " <span class='msm-meta'>&mdash; no flagged requests in this window</span></summary>",
          "<div class='msm-site-chips' style='margin-top:10px'>";
    print map { "<span class='msm-chip-sm msm-chip-site'>" . &html_escape($_->{name}) . "</span>" } @quiet;
    print "</div></details>\n";
}

print "<p class='msm-meta'>Requests are matched to a site by their Host header against ServerName and ServerAlias.</p>\n";

print_page_end();
&ui_print_footer("", $text{'index_return'});
