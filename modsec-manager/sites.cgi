#!/usr/bin/perl
# Per-site view: which Apache virtual hosts ModSecurity flags most.
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Sites", "");
print_nav('sites.cgi', 'Which websites on this server ModSecurity flags most, matched by ServerName and ServerAlias.');

my %p = paths();
my $history = ($in{'history'} || 0) =~ /^([0-7])$/ ? $1 : 0;
my ($raw, $txs, $file, $err) = read_recent_log('audit', $history);
my @vh = apache_vhosts();

print_history_form('sites.cgi', $file, $history);
print "<p class='msm-meta'>", scalar(@vh), " virtual hosts in <span class='msm-path'>",
      &html_escape($p{apache_sites_dir}), "</span> &middot; ", scalar(@$txs), " flagged requests in the log window.</p>\n";
if ($err) {
    print "<div class='msm-alert msm-alert-info'><div class='msm-alert-text'>", &html_escape($err), "</div></div>\n";
}

# Group events by site.
my (%s, %unmatched);
foreach my $tx (@$txs) {
    my $site = site_for_host($tx->{host}, \@vh);
    my $key = $site || '';
    if (!$site) {
        $unmatched{norm_host($tx->{host}) || '(no Host header)'}++;
    }
    my $e = $s{$key} ||= { events => 0, blocked => 0, txs => [], last => '' };
    $e->{events}++;
    $e->{blocked}++ if tx_blocked($tx);
    push(@{$e->{txs}}, $tx);
    $e->{last} ||= $tx->{time};   # $txs is newest first
}

my $cnt = sub { $s{$_[0]} ? $s{$_[0]}{events} : 0 };
my @rows = sort { $cnt->($b->{name}) <=> $cnt->($a->{name}) || $a->{name} cmp $b->{name} } @vh;
my $max = 1;
foreach my $v (@rows) { my $n = $cnt->($v->{name}); $max = $n if ($n > $max); }
$max = $s{''}{events} if ($s{''} && $s{''}{events} > $max);

print "<div class='msm-legend'><span><span class='msm-sw' style='background:var(--s2)'></span>Blocked</span>",
      "<span><span class='msm-sw' style='background:var(--s1)'></span>Logged only</span></div>\n";
print "<div class='msm-wrap'><table class='table msm-table'>\n";
print "<tr><th>Site</th><th style='min-width:160px'>Flagged requests</th><th>Blocked</th><th>Top rule</th><th>Top path</th><th>Last event</th><th></th></tr>\n";

sub site_row {
    my ($label, $sub, $e, $logs_href, $site_host) = @_;
    $e ||= { events => 0, blocked => 0, txs => [] };
    my $n = $e->{events};
    my $logged = $n - $e->{blocked};
    my ($top_rule) = grep { !is_score_rule($_->[0]) } top_values($e->{txs}, \&tx_rule_ids);
    my ($top_path) = top_values($e->{txs}, \&tx_path, 1);
    my $pct = $n ? sprintf("%d%%", 100 * $e->{blocked} / $n + 0.5) : '';
    print "<tr><td><b>", &html_escape($label), "</b>", ($sub ? "<div class='msm-card-sub'>$sub</div>" : ""), "</td>";
    print "<td><div class='msm-hbar-track' style='margin-bottom:4px'>",
          ($e->{blocked} ? "<span style='width:" . (100 * $e->{blocked} / $max) . "%;background:var(--s2)'></span>" : ""),
          ($logged ? "<span style='width:" . (100 * $logged / $max) . "%;background:var(--s1)'></span>" : ""),
          "</div>$n</td>";
    print "<td>", $e->{blocked}, ($pct ? " <span class='msm-meta'>($pct)</span>" : ""), "</td>";
    print "<td>", ($top_rule ? "<b>" . &html_escape($top_rule->[0]) . "</b> <span class='msm-meta'>&times;$top_rule->[1]</span>" : ""), "</td>";
    print "<td>", ($top_path ? "<span class='msm-path'>" . &html_escape($top_path->[0]) . "</span> <span class='msm-meta'>&times;$top_path->[1]</span>" : ""), "</td>";
    print "<td style='white-space:nowrap'>", &html_escape(short_log_time($e->{last})), "</td>";
    print "<td style='white-space:nowrap'>";
    if ($n) {
        print "<a class='msm-btn' href='$logs_href'>Logs</a> ";
        if ($top_rule && can_edit()) {
            print "<a class='msm-btn' href='exclusion_builder.cgi?rule=", &url_escape($top_rule->[0]),
                  ($site_host ? "&amp;host=" . &url_escape($site_host) : ""),
                  ($history ? "&amp;history=$history" : ""), "'>Exclude top rule</a>";
        }
    }
    print "</td></tr>\n";
}

foreach my $v (@rows) {
    my @sub;
    push(@sub, "Aliases: " . &html_escape(join(', ', @{$v->{aliases}}))) if (@{$v->{aliases}});
    push(@sub, "Ports: " . &html_escape(join(', ', @{$v->{ports}}))) if (@{$v->{ports}});
    site_row($v->{name}, join(' &middot; ', @sub), $s{$v->{name}},
             "logs.cgi?site=" . &url_escape($v->{name}) . ($history ? "&amp;history=$history" : ""), $v->{name});
}
if ($s{''}) {
    my @h = sort { $unmatched{$b} <=> $unmatched{$a} } keys %unmatched;
    my $list = join(', ', map { &html_escape($_) . " ($unmatched{$_})" } @h[0 .. ($#h < 5 ? $#h : 5)]);
    site_row("Other hosts", "Requests whose Host matches no virtual host (often scanners using the IP): $list",
             $s{''}, "logs.cgi" . ($history ? "?history=$history" : ""), '');
}
print "</table></div>\n";
if (!@vh) {
    print "<div class='msm-alert'><div class='msm-alert-text'>No virtual hosts were found in <span class='msm-path'>",
          &html_escape($p{apache_sites_dir}), "</span>. Set the sites directory in Module Config.</div></div>\n";
}
print "<p class='msm-meta'>Requests are matched to a site by their Host header against ServerName and ServerAlias.</p>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
