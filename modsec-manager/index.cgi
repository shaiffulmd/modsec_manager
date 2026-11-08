#!/usr/bin/perl
require './modsec-lib.pl';

&ui_print_header(undef, $text{'index_title'}, "", undef, 1, 1);
print_ui_css();

my %s = status_overview();
my %p = %{$s{paths}};
my %crs = crs_settings();
my %al = alert_settings();
my $edit = can_edit();

print_nav('index.cgi');
print_readonly_notice();

# --- Summary cards ----------------------------------------------------------

my %engine = (
    'On'            => ['ok',   'Blocking',      'Requests over the anomaly threshold are blocked'],
    'DetectionOnly' => ['warn', 'Detection only', 'Attacks are logged but not blocked'],
    'Off'           => ['bad',  'Off',           'Traffic is not inspected'],
    'Unknown'       => ['bad',  'Unknown',       'No SecRuleEngine directive found'],
);
my $e = $engine{$s{engine}} || $engine{'Unknown'};

my ($excl_state, $excl_value, $excl_sub);
if ($s{excl_include} && $s{excl_exists}) {
    ($excl_state, $excl_value, $excl_sub) = ('ok', 'Active', "Loaded by $s{excl_include}");
} elsif ($s{excl_include}) {
    ($excl_state, $excl_value, $excl_sub) = ('na', 'Empty', 'File not created yet; it will load once created');
} else {
    ($excl_state, $excl_value, $excl_sub) = ('warn', 'Not loaded', 'The exclusions file is not included');
}

my @cards = (
    ['Rule engine', $e->[0], $e->[1], $e->[2]],
    ['Apache module', $s{module_on} ? 'ok' : 'bad', $s{module_on} ? 'Enabled' : 'Disabled',
        $s{mod_version} ? "libapache2-mod-security2 $s{mod_version}" : 'Package not installed'],
    ['OWASP CRS', $s{crs_version} ? 'ok' : 'warn', $s{crs_version} || 'Not installed',
        "$s{rule_files} rule files" . ($s{rule_disabled} ? ", $s{rule_disabled} disabled" : "")],
    ['Exclusions', $excl_state, $excl_value, $excl_sub],
    ['Audit log', $s{audit_exists} ? 'ok' : 'warn',
        $s{audit_exists} ? human_size($s{audit_size}) : 'Missing', $s{audit_log}],
);

print "<div class='msm-cards'>\n";
foreach my $c (@cards) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]), "</div>",
          "<div class='msm-card-value'>", status_dot($c->[1]), &html_escape($c->[2]), "</div>",
          "<div class='msm-card-sub'>", &html_escape($c->[3]), "</div></div>\n";
}
print "</div>\n";

# --- Things that need attention ---------------------------------------------

sub action_button {
    my ($action, $label) = @_;
    return '' if (!$edit);
    return "<form method='post' action='actions.cgi' style='margin:0'>" .
           &ui_hidden("action", $action) . msm_submit($label, 'primary') . "</form>";
}
sub link_button {
    my ($href, $label) = @_;
    return "<a class='msm-btn' href='$href'>" . &html_escape($label) . "</a>";
}

my @alerts;
if (!$s{mod_version}) {
    push(@alerts, ['bad', 'The <b>libapache2-mod-security2</b> package is not installed. Run '.
        '<code>sudo apt install libapache2-mod-security2 modsecurity-crs</code> on the server.', '']);
}
if (!$s{conf_exists}) {
    push(@alerts, ['bad', '<b>' . &html_escape($p{modsecurity_conf}) . '</b> does not exist, so ModSecurity '.
        'runs without its main configuration.',
        $s{rec_exists} ? action_button('create_config', 'Create from recommended') : '']);
}
if (!$s{module_on}) {
    push(@alerts, ['bad', 'The Apache <b>security2</b> module is not enabled.',
        action_button('enable_module', 'Enable module')]);
}
if ($s{engine} eq 'DetectionOnly') {
    push(@alerts, ['warn', 'ModSecurity is in <b>DetectionOnly</b> mode: attacks are logged but not blocked. '.
        'Switch to <b>On</b> once the logs show no false positives.', link_button('mode.cgi', 'Change mode')]);
} elsif ($s{engine} ne 'On' && $s{conf_exists}) {
    push(@alerts, ['bad', 'The rule engine is <b>' . &html_escape($s{engine}) . '</b>: traffic is not inspected.',
        link_button('mode.cgi', 'Change mode')]);
}
if (!$s{crs_version} && $s{mod_version}) {
    push(@alerts, ['warn', 'The OWASP Core Rule Set is not installed, so few or no attack rules are loaded. '.
        'Run <code>sudo apt install modsecurity-crs</code>.', '']);
}
if (!$s{excl_include}) {
    push(@alerts, ['warn', 'The custom exclusions file is not loaded by ModSecurity.',
        action_button('include', 'Include it')]);
}
if (!$s{audit_exists}) {
    push(@alerts, ['info', 'No audit log at <span class="msm-path">' . &html_escape($s{audit_log}) .
        '</span> yet. It is created on the first logged event.', '']);
}

if (@alerts) {
    print "<div class='msm-alerts'>\n";
    foreach my $a (@alerts) {
        my $cls = $a->[0] eq 'bad' ? ' msm-alert-bad' : $a->[0] eq 'info' ? ' msm-alert-info' : '';
        print "<div class='msm-alert$cls'><div class='msm-alert-text'>$a->[1]</div>$a->[2]</div>\n";
    }
    print "</div>\n";
}

# --- Details ----------------------------------------------------------------

sub kv_table {
    my ($title, @rows) = @_;
    my $h = "<div class='msm-panel'><div class='msm-panel-title' style='margin-bottom:8px'>" . &html_escape($title) . "</div><table class='msm-kv'>";
    foreach my $r (@rows) {
        my ($k, $state, $v, $is_path) = @$r;
        $h .= "<tr><td class='msm-k'>" . &html_escape($k) . "</td><td class='msm-v'>" .
              "<div class='msm-vrow'>" . ($state ? status_dot($state) : "") .
              "<span" . ($is_path ? " class='msm-path'" : "") . ">" . &html_escape($v) .
              "</span></div></td></tr>";
    }
    return $h . "</table></div>\n";
}
sub file_row {
    my ($label, $file, $exists, $missing_state) = @_;
    return [$label, $exists ? 'ok' : ($missing_state || 'bad'), $exists ? $file : "Missing: $file", 1];
}

print "<div class='msm-grid2'>\n";
print kv_table('Packages',
    ['ModSecurity for Apache', $s{mod_version} ? 'ok' : 'bad', $s{mod_version} || 'Not installed'],
    ['OWASP Core Rule Set', $s{crs_version} ? 'ok' : 'warn', $s{crs_version} || 'Not installed'],
    ['Apache security2 module', $s{module_on} ? 'ok' : 'bad', $s{module_on} ? 'Enabled' : 'Not enabled'],
    ['SecRuleEngine', $e->[0], $s{engine}],
    ['CRS paranoia level', $crs{exists} ? 'ok' : 'na', $crs{exists} ? "PL$crs{paranoia}, inbound threshold $crs{inbound}" : 'crs-setup.conf not found'],
    ['Alerts', $al{enabled} ? 'ok' : 'na', $al{enabled} ? "On ($al{threshold} blocks / $al{interval} min)" : 'Off'],
);
print kv_table('Configuration files',
    file_row('Main config', $p{modsecurity_conf}, $s{conf_exists}),
    file_row('Recommended template', $p{modsecurity_recommended}, $s{rec_exists}, 'na'),
    file_row('Apache module config', $p{apache_security_conf}, $s{apache_exists}),
    file_row('Custom exclusions', $p{custom_exclusions}, $s{excl_exists}, 'na'),
);
print kv_table('Exclusions and logs',
    ['Exclusions loaded by', $s{excl_include} ? 'ok' : 'warn', $s{excl_include} || 'Not included', 1],
    file_row('Audit log', $s{audit_log}, $s{audit_exists}, 'warn'),
    ['Error log', -e $p{error_log} ? 'ok' : 'na', $p{error_log}, 1],
);
print kv_table('Rules',
    ['Rule files', $s{rule_files} ? 'ok' : 'warn', "$s{rule_files} found, $s{rule_disabled} disabled"],
    map { ['Directory', '', $_, 1] } @{$s{rule_dirs}},
);
print "</div>\n";

# --- Shortcuts --------------------------------------------------------------

my @tiles = (
    ['sites.cgi',             'globe',    'Sites',             'Which websites get flagged most'],
    ['logs.cgi',              'activity', 'Logs',              'Charts, false-positive hints and attackers'],
    ['exclusion_builder.cgi', 'wand',     'Exclusion builder', 'Exclude a rule for one site, path or field'],
    ['mode.cgi',              'sliders',  'Protection',        'Engine mode, paranoia level and thresholds'],
    ['alerts.cgi',            'bell',     'Alerts',            'E-mail or Telegram when blocks spike'],
    ['rules.cgi',             'list',     'Rules',             'Enable, disable or edit rule files'],
    ['config_editor.cgi',     'file',     'Config files',      'Edit modsecurity.conf and security2.conf'],
    ['actions.cgi',           'tool',     'Maintenance',       'Config test, reload and package updates'],
);
print "<div class='msm-h'>Manage</div>\n<div class='msm-tiles'>\n";
foreach my $t (@tiles) {
    print "<a class='msm-tile' href='$t->[0]'><span class='msm-tile-ico'>", icon($t->[1], 18), "</span><span><b>",
          &html_escape($t->[2]), "</b><span>", &html_escape($t->[3]), "</span></span></a>\n";
}
print "</div>\n";

print_page_end();

&ui_print_footer("/", $text{'index'});
