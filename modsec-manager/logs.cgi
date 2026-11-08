#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, $text{'logs_title'}, "");
print_nav('logs.cgi', 'What ModSecurity saw recently. Click any bar to filter every chart and list on this page.');

my $source = ($in{'source'} || '') eq 'error' ? 'error' : 'audit';
my %f;
foreach my $k ('rule', 'ip', 'host', 'path', 'site') {
    $f{$k} = defined($in{$k}) ? $in{$k} : '';
    $f{$k} =~ s/[\r\n]//g;
}
$f{blocked} = $in{'blocked'} ? 1 : 0;
$f{history} = ($in{'history'} || 0) =~ /^([0-7])$/ ? $1 : 0;

# Link to this page with the current filters, overridden by %o.
sub logs_url {
    my (%o) = @_;
    my %q = (source => $source, %f, %o);
    my @p = map { "$_=" . &url_escape($q{$_}) } grep { $q{$_} ne '' && $q{$_} ne '0' } sort keys %q;
    return "logs.cgi" . (@p ? "?" . join("&amp;", @p) : "");
}

my ($raw, $all, $file, $err) = read_recent_log($source, $f{history});
# A site filter matches its ServerName and every ServerAlias.
my @vhosts = apache_vhosts();
my $site_hosts;
if ($f{site} ne '') {
    my ($v) = grep { $_->{name} eq norm_host($f{site}) } @vhosts;
    $site_hosts = { map { $_ => 1 } ($v ? ($v->{name}, grep { !/[*?]/ } @{$v->{aliases}}) : norm_host($f{site})) };
}
my @txs = filter_transactions($all, %f, hosts => $site_hosts);


# --- Filters ----------------------------------------------------------------

print "<form method='get' action='logs.cgi' class='msm-filters'>";
foreach my $k ('rule', 'ip', 'host', 'path', 'site') {
    print &ui_hidden($k, $f{$k}) if ($f{$k} ne '');
}
print "<label>Source <select name='source'>",
      "<option value='audit'", ($source eq 'audit' ? " selected" : ""), ">ModSecurity audit log</option>",
      "<option value='error'", ($source eq 'error' ? " selected" : ""), ">Apache error log</option>",
      "</select></label>";
print history_select($file, $f{history});
print "<label><input type='checkbox' name='blocked' value='1'", ($f{blocked} ? " checked" : ""),
      "> Blocked only</label>";
print &ui_submit("Show");
my %flabel = (site => 'Site', rule => 'Rule', ip => 'Client', host => 'Host', path => 'Path');
my @active = grep { $f{$_} ne '' } ('site', 'rule', 'ip', 'host', 'path');
foreach my $k (@active) {
    print "<span class='msm-chip'>", $flabel{$k}, ": <b>", &html_escape($f{$k}), "</b>",
          "<a href='", logs_url($k => ''), "' title='Remove filter' aria-label='Remove filter'>&times;</a></span>";
}
if (@active || $f{blocked}) {
    print "<a href='logs.cgi?source=$source" . ($f{history} ? "&amp;history=$f{history}" : "") . "'>Clear filters</a>";
}
print "</form>\n";

if ($err) {
    print "<div class='msm-alert msm-alert-info'><div class='msm-alert-text'>", &html_escape($err),
          "</div></div>\n";
    print_page_end();
    &ui_print_footer("", $text{'index_return'});
    exit;
}

my ($buckets, $unit) = event_timeline(\@txs, $all);
my $span = '';
if (@$buckets) {
    $span = " covering " . bucket_label($buckets->[0]{start}, $unit, 1) . " &ndash; " .
            bucket_label($buckets->[-1]{start}, $unit, 1);
}
print "<p class='msm-meta'><span class='msm-path'>", &html_escape($file), "</span>",
      ($f{history} ? " + rotated logs" : ""), " &middot; last ",
      scalar(@$raw), " lines, ", scalar(@$all), " events", $span, ".</p>\n";

# --- Stat tiles -------------------------------------------------------------

my $blocked = grep { tx_blocked($_) } @txs;
my %clients = map { ($_->{client} || '') => 1 } @txs;
delete $clients{''};
my @rules_fired = rule_hit_summary(\@txs);
my $pct = @txs ? sprintf("%d%% of events", 100 * $blocked / @txs + 0.5) : '';

print "<div class='msm-cards'>\n";
foreach my $c (['Events', scalar(@txs), @active || $f{blocked} ? 'Matching the filters' : 'In the log window'],
               ['Blocked', $blocked, $pct || 'None'],
               ['Logged only', @txs - $blocked, 'Matched rules, not blocked'],
               ['Clients', scalar(keys %clients), 'Distinct IP addresses'],
               ['Rules triggered', scalar(@rules_fired), 'Distinct rule IDs']) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]),
          "</div><div class='msm-card-value'>", &html_escape($c->[1]),
          "</div><div class='msm-card-sub'>", &html_escape($c->[2]), "</div></div>\n";
}
print "</div>\n";

if (!@txs) {
    print "<div class='msm-alert msm-alert-info'><div class='msm-alert-text'>",
          (@$all ? "No events match the current filters." :
                   "No ModSecurity events were found in the recent log window."),
          "</div></div>\n";
}

my $legend = "<div class='msm-legend'>" .
             "<span><span class='msm-sw' style='background:var(--s2)'></span>Blocked</span>" .
             "<span><span class='msm-sw' style='background:var(--s1)'></span>Logged only</span></div>";

# Round the axis maximum up to 1, 2 or 5 x 10^n.
sub nice_max {
    my ($n) = @_;
    return 1 if ($n <= 1);
    my $p = 10 ** int(log($n) / log(10));
    foreach my $m (1, 2, 5, 10) {
        return $m * $p if ($m * $p >= $n);
    }
    return 10 * $p;
}

# --- Timeline ---------------------------------------------------------------

if (@$buckets) {
    my $max = 0;
    foreach my $b (@$buckets) { $max = $b->{total} if ($b->{total} > $max); }
    my $top = nice_max($max);
    print "<div class='msm-chart'><div class='msm-chart-title'>Events over time</div>",
          "<div class='msm-chart-sub'>Per ", $unit, ", server local time</div>", $legend;
    print "<div class='msm-plot'>";
    foreach my $frac (1, 0.5) {
        my $y = 170 * (1 - $frac);
        print "<div class='msm-gridline' style='top:${y}px'></div>",
              "<div class='msm-ytick' style='top:${y}px'>", ($top * $frac == int($top * $frac) ? $top * $frac : ''), "</div>";
    }
    print "<div class='msm-ytick' style='top:170px'>0</div>";
    print "<div class='msm-cols'>";
    my $n = scalar(@$buckets);
    for (my $i = 0; $i < $n; $i++) {
        my $b = $buckets->[$i];
        my $logged = $b->{total} - $b->{blocked};
        my $tipcls = $i < $n * 0.15 ? ' msm-tip-l' : $i > $n * 0.85 ? ' msm-tip-r' : '';
        my $hb = 170 * $b->{blocked} / $top;
        my $hl = 170 * $logged / $top;
        print "<div class='msm-col'>";
        print "<div class='msm-tip$tipcls'><b>", bucket_label($b->{start}, $unit, 1), "</b><br>",
              "$b->{total} events<br>$b->{blocked} blocked &middot; $logged logged only</div>";
        print "<div class='msm-seg", ($logged ? " msm-seg-top" : ""), "' style='height:${hl}px;background:var(--s1)'></div>" if ($logged);
        print "<div class='msm-seg", ($logged ? "" : " msm-seg-top"), "' style='height:${hb}px;background:var(--s2)'></div>" if ($b->{blocked});
        print "</div>";
    }
    print "</div>";
    # Sparse x labels: about 8 across the axis.
    my $every = $n <= 12 ? 1 : int(($n + 7) / 8);
    print "<div class='msm-xlabels'>";
    for (my $i = 0; $i < $n; $i++) {
        my $show = ($i % $every == 0);
        print "<span>", ($show ? "<i>" . bucket_label($buckets->[$i]{start}, $unit, 0) . "</i>" : ""), "</span>";
    }
    print "</div></div></div>\n";
}

# --- Top N charts -----------------------------------------------------------

sub hbar_chart {
    my ($title, $sub, $key, $rows, $labeler) = @_;
    my $h = "<div class='msm-chart'><div class='msm-chart-title'>" . &html_escape($title) .
            "</div><div class='msm-chart-sub'>" . &html_escape($sub) . "</div>";
    if (!@$rows) {
        return $h . "<div class='msm-empty'>No data</div></div>\n";
    }
    my $max = $rows->[0][1] || 1;
    $h .= "<div class='msm-hbars'>";
    foreach my $r (@$rows) {
        my ($val, $count, $blk) = @$r;
        my $on = $f{$key} eq $val;
        my $href = logs_url($key => $on ? '' : $val);
        my $wb = 100 * $blk / $max;
        my $wl = 100 * ($count - $blk) / $max;
        my $tip = "$count events: $blk blocked, " . ($count - $blk) . " logged only. " .
                  ($on ? "Click to remove filter" : "Click to filter");
        $h .= "<a class='msm-hbar" . ($on ? " msm-on" : "") . "' href='$href' title='" . &html_escape($tip) . "'>" .
              "<span class='msm-hbar-label'>" . $labeler->($val) . "</span>" .
              "<span class='msm-hbar-track'>" .
              ($blk ? "<span style='width:$wb%;background:var(--s2)'></span>" : "") .
              ($count - $blk ? "<span style='width:$wl%;background:var(--s1)'></span>" : "") .
              "</span><span class='msm-hbar-val'>$count</span></a>";
    }
    return $h . "</div></div>\n";
}

if (@txs) {
    my %rule_msg = map { $_->{id} => $_->{msg} } @rules_fired;
    # Anomaly-score totals fire on every blocked request and would dwarf the
    # rules that actually matched, so they are left out of this chart.
    my @rule_rows = grep { !is_score_rule($_->[0]) }
                    top_values(\@txs, \&tx_rule_ids);
    splice(@rule_rows, 10) if (@rule_rows > 10);
    my $plain = sub { &html_escape($_[0]) };

    print "<div class='msm-grid2'>\n";
    print hbar_chart('Top rules', 'Requests per detection rule (anomaly-score totals excluded)', 'rule', \@rule_rows, sub {
        "<b>" . &html_escape($_[0]) . "</b> <small>" . &html_escape($rule_msg{$_[0]} || '') . "</small>" });
    print hbar_chart('Top clients', 'Requests by client IP', 'ip',
        [ top_values(\@txs, sub { $_[0]{client} }, 10) ], $plain);
    print hbar_chart('Top sites', 'Requests by website (virtual host)', 'site',
        [ top_values(\@txs, sub { site_for_host($_[0]{host}, \@vhosts) || norm_host($_[0]{host}) }, 10) ], $plain);
    print hbar_chart('Top paths', 'Requests by URL path (query string removed)', 'path',
        [ top_values(\@txs, \&tx_path, 10) ], $plain);
    print "</div>\n";
    print "<p class='msm-meta'>Click a bar to filter every chart and table on this page.</p>\n";

    # --- Insights ---
    my ($fp, $bad) = log_insights(\@txs);
    print "<div class='msm-grid2'>\n";
    print "<div class='msm-chart'><div class='msm-chart-title'>Possible false positives</div>",
          "<div class='msm-chart-sub'>One rule on one site and path, tripped by 3 or more ordinary clients</div>";
    if (@$fp) {
        foreach my $e (@$fp) {
            my $b = "exclusion_builder.cgi?rule=" . &url_escape($e->{rule}) . "&amp;host=" . &url_escape($e->{host}) .
                    "&amp;path=" . &url_escape($e->{path}) . "&amp;match=exact" .
                    ($e->{target} ? "&amp;scope=target&amp;target=" . &url_escape($e->{target}) : "&amp;scope=rule") .
                    ($f{history} ? "&amp;history=$f{history}" : "");
            print "<div class='msm-ins'><div class='msm-ins-main'><b>", &html_escape($e->{rule}), "</b> ",
                  &html_escape($e->{msg} || ''),
                  "<div class='msm-ins-sub'><span class='msm-path'>", &html_escape(($e->{host} || '?') . $e->{path}), "</span>",
                  ($e->{target} ? " &middot; in " . &html_escape($e->{target}) : ""), "</div></div>",
                  "<div class='msm-ins-side'><span><b>$e->{nclients}</b> clients &middot; $e->{hits} hits</span>",
                  (can_edit() ? "<a class='msm-btn' href='$b'>Exclude</a>" : ""), "</div></div>";
        }
    } else {
        print "<div class='msm-empty'>None found. Rules here are only tripped by a few clients.</div>";
    }
    print "</div>\n";
    print "<div class='msm-chart'><div class='msm-chart-title'>Likely attackers</div>",
          "<div class='msm-chart-sub'>Scanners, or clients tripping 4+ rules or 20+ requests. Do not exclude these.</div>";
    if (@$bad) {
        foreach my $a (@$bad) {
            print "<div class='msm-ins'><div class='msm-ins-main'><a href='", logs_url(ip => $a->{ip}), "'><b>",
                  &html_escape($a->{ip}), "</b></a><div class='msm-ins-sub'>", &html_escape($a->{reason}), "</div></div>",
                  "<div class='msm-ins-side'><span><b>$a->{events}</b> requests &middot; $a->{blocked} blocked</span></div></div>";
        }
        print "<p class='msm-meta' style='margin:10px 0 0'>To block an address outright use the firewall (Webmin &gt; Networking) or Cloudflare (see the <a href='cloudflare.cgi'>Cloudflare checks</a>), not ModSecurity exclusions.</p>";
    } else {
        print "<div class='msm-empty'>None found.</div>";
    }
    print "</div>\n</div>\n";
}

# --- Rules table with exclusion shortcuts ------------------------------------

if (@rules_fired) {
    print "<div class='msm-h'>Rules that fired</div>\n";
    print "<div class='msm-wrap'><table class='msm-table'>\n";
    print "<tr><th>Rule</th><th>Hits</th><th>Severity</th><th>Message</th>",
          (can_edit() ? "<th>Exclusion</th>" : ""), "</tr>\n";
    foreach my $h (@rules_fired) {
        print "<tr><td><a href='", logs_url(rule => $h->{id}), "'>", &html_escape($h->{id}), "</a></td>";
        print "<td>", &html_escape($h->{count}), "</td>";
        print "<td>", &html_escape($h->{severity} || ''), "</td>";
        print "<td>", &html_escape($h->{msg} || ''), "</td>";
        if (can_edit()) {
            print "<td>";
            if (is_score_rule($h->{id})) {
                print "<i>score total</i></td></tr>\n";
                next;
            }
            my $scope_host = $f{host} ne '' ? $f{host} : $f{site};
            print "<a class='msm-btn' href='exclusion_builder.cgi?rule=", &url_escape($h->{id}),
                  ($scope_host ne '' ? "&amp;host=" . &url_escape($scope_host) : ""),
                  ($f{path} ne '' ? "&amp;path=" . &url_escape($f{path}) . "&amp;match=exact" : ""),
                  ($f{history} ? "&amp;history=$f{history}" : ""), "'>Build exclusion</a>";
            print "</td>";
        }
        print "</tr>\n";
    }
    print "</table></div>\n";
    print "<p class='msm-meta'>Only add exclusions for confirmed false positives. Rules 949110/980130 are the CRS ",
          "anomaly-score totals; exclude the individual rules that raised the score instead.</p>\n";
}

# --- Event list -------------------------------------------------------------

if (@txs) {
    my $limit = 200;
    print "<div class='msm-h'>Recent events",
          (@txs > $limit ? " <small style='font-weight:400;opacity:.65'>(newest $limit of " . scalar(@txs) . ")</small>" : ""),
          "</div>\n";
    # One card per request: works at any width, unlike a 7-column table.
    print "<div class='msm-events'>\n";
    foreach my $tx (@txs[0 .. ($#txs < $limit - 1 ? $#txs : $limit - 1)]) {
        my $blk = tx_blocked($tx);
        my ($method, $uri) = ($tx->{request} || '') =~ /^(\S+)\s+(\S+)/;
        $uri = $tx->{request} || '' if (!defined $uri);
        print "<div class='msm-ev'>";
        print "<div class='msm-ev-meta'>",
              "<span class='msm-ev-res'>", status_dot($blk ? 'bad' : 'warn'), ($blk ? "Blocked" : "Logged"),
              ($tx->{status} ? " <span class='msm-meta'>" . &html_escape($tx->{status}) . "</span>" : ""), "</span>",
              "<span class='msm-ev-time' title='", &html_escape($tx->{time} || ''), "'>", &html_escape(short_log_time($tx->{time})), "</span>",
              "</div>";
        print "<div class='msm-ev-body'>";
        print "<div class='msm-ev-req'>", ($method ? "<span class='msm-ev-method'>" . &html_escape($method) . "</span>" : ""),
              "<span class='msm-path'>", &html_escape($uri), "</span></div>";
        print "<div class='msm-ev-who'>",
              ($tx->{host} ? &html_escape($tx->{host}) : "<i>no host</i>"), " &middot; ",
              ($tx->{client} ? "<a href='" . logs_url(ip => $tx->{client}) . "'>" . &html_escape($tx->{client}) . "</a>" : "unknown client"),
              "</div>";
        print "<div class='msm-ev-rules'>";
        foreach my $m (@{$tx->{messages}}) {
            my $score = is_score_rule($m->{id});
            my $tg = message_target($m);
            print "<span class='msm-rule", ($score ? " msm-rule-score" : ""), "' title='",
                  &html_escape($m->{data} || $m->{text} || ''), "'>";
            print "<b>", &html_escape($m->{id}), "</b> " if ($m->{id});
            print &html_escape($score ? 'anomaly score' : ($m->{msg} || $m->{text} || ''));
            print " <span class='msm-meta'>in ", &html_escape($tg), "</span>" if ($tg && !$score);
            print "</span>";
        }
        print "</div></div></div>\n";
    }
    print "</div>\n";
    print "<p class='msm-meta'>Hover a rule to see the matched data.</p>\n";
}

my @show = @$raw > 500 ? @$raw[-500 .. -1] : @$raw;
print "<details><summary>Raw log (last ", scalar(@show), " lines)</summary>\n";
print "<pre>", &html_escape(join("\n", @show)), "</pre>\n";
print "</details>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
