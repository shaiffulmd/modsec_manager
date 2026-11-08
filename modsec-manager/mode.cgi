#!/usr/bin/perl
# Protection: rule engine mode and OWASP CRS paranoia / anomaly thresholds.
require './modsec-lib.pl';

&ui_print_header(undef, "Protection", "");
print_nav('mode.cgi', 'How strictly ModSecurity inspects traffic. Changes are tested before they are kept; '.
                      'reload Apache afterwards to apply them.');
print_readonly_notice();
my $dis = can_edit() ? '' : ' disabled';

# --- Rule engine ------------------------------------------------------------

my $mode = current_engine_mode();
my @modes = (
    ['On',            'Blocking',       'Block requests that reach the anomaly threshold. Recommended once tuned.'],
    ['DetectionOnly', 'Detection only', 'Log matches but never block. Use while you tune exclusions.'],
    ['Off',           'Off',            'Do not inspect traffic at all.'],
);
print "<div class='msm-panel'><div class='msm-panel-title'>Rule engine</div>",
      "<div class='msm-panel-sub'>SecRuleEngine is currently <b>", &html_escape($mode), "</b>.</div>\n";
print "<form method='post' action='save_mode.cgi'><div class='msm-choices'>";
foreach my $m (@modes) {
    print "<label class='msm-choice'><input type='radio' name='mode' value='$m->[0]'",
          ($mode eq $m->[0] ? " checked" : ""), "$dis><span><b>", &html_escape($m->[1]),
          " <span class='msm-badge'>$m->[0]</span></b><small>", &html_escape($m->[2]), "</small></span></label>";
}
print "</div>";
print "<div class='msm-actions'>", msm_submit("Save mode", 'primary'), "</div>" if (can_edit());
print "</form></div>\n";

# --- CRS tuning -------------------------------------------------------------

my %c = crs_settings();
print "<div class='msm-panel'><div class='msm-panel-title'>OWASP CRS tuning</div>";
if (!$c{exists}) {
    print "<div class='msm-panel-sub'>&nbsp;</div>",
          callout('warn', "CRS setup file not found: <span class='msm-path'>" . &html_escape($c{file}) .
                  "</span>. Install <code>modsecurity-crs</code> or set its path in Module Config.");
} else {
    print "<div class='msm-panel-sub'>Stored in <span class='msm-path'>", &html_escape($c{file}), "</span>",
          ($c{crs4} ? " (CRS 4)" : " (CRS 3)"), ". Values marked <span class='msm-badge'>default</span> are not set in the file.</div>\n";
    my $dflt = sub { $c{set}{$_[0]} ? '' : " <span class='msm-badge'>default</span>" };
    my @pl = (
        [1, 'Recommended for most sites. Very few false positives.'],
        [2, 'Adds more SQL/XSS patterns. Expect some tuning.'],
        [3, 'Strict. Many false positives; for sensitive applications.'],
        [4, 'Paranoid. Blocks a lot of normal traffic.'],
    );
    print "<form method='post' action='save_crs.cgi'>";
    my $choices = "<div class='msm-choices'>";
    foreach my $p (@pl) {
        $choices .= "<label class='msm-choice'><input type='radio' name='paranoia' value='$p->[0]'" .
                    ($c{paranoia} == $p->[0] ? " checked" : "") . "$dis><span><b>Level $p->[0]</b><small>" .
                    &html_escape($p->[1]) . "</small></span></label>";
    }
    $choices .= "</div>";
    print field_row("Paranoia level" . $dflt->('paranoia'), $choices,
        "Higher levels enable more rules. Raise one level at a time and watch the logs.");
    print field_row("Inbound anomaly threshold" . $dflt->('inbound'),
        "<input name='inbound' size='6' inputmode='numeric' value='" . &html_escape($c{inbound}) . "'$dis>",
        "A request is blocked when its score reaches this value. A critical match scores 5. "
        . "Raise it (e.g. 10&ndash;20) temporarily while tuning, then return to 5.");
    print field_row("Outbound anomaly threshold" . $dflt->('outbound'),
        "<input name='outbound' size='6' inputmode='numeric' value='" . &html_escape($c{outbound}) . "'$dis>",
        "Score at which a response (for example one leaking error messages) is blocked. Default 4.");
    print "<div class='msm-actions'>", msm_submit("Save CRS settings", 'primary'), "</div>" if (can_edit());
    print "</form>";
}
print "</div>\n";

print_page_end();
&ui_print_footer("", $text{'index_return'});
