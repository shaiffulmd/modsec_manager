#!/usr/bin/perl
# Maintenance: config test, reload, first-time setup and package updates.
require './modsec-lib.pl';

&ReadParse();
my $action = defined($in{'action'}) ? $in{'action'} : '';
if ($action ne '' && $action ne 'configtest') {
    require_edit();
    require_post();
}
&ui_print_header(undef, $text{'actions_title'}, "");
print_nav('actions.cgi', $action ? '' :
    'Check the Apache configuration, reload safely, finish first-time setup and keep the packages up to date.');

my %p = paths();

if ($action eq 'reload') {
    my ($code, $out) = apache_reload();
    print callout($code == 0 ? 'ok' : 'bad', $code == 0 ? "Configuration is valid and Apache was reloaded."
                                                       : "Apache was <b>not</b> reloaded. Fix the error below first.");
    &print_command_result('Apache reload', $code, $out);
} elsif ($action eq 'create_config') {
    my ($msg, $created) = create_config_from_recommended();
    print callout($created ? 'ok' : 'info', &html_escape($msg));
    if ($created) {
        my ($code, $out) = apache_configtest();
        if ($code != 0) {
            remove_created_file($p{modsecurity_conf});
            print callout('bad', "Config test failed. Removed the newly created <span class='msm-path'>" .
                                 &html_escape($p{modsecurity_conf}) . "</span>.");
        }
        &print_command_result('Apache config test', $code, $out);
        print_reload_form() if ($code == 0);
    }
} elsif ($action eq 'enable_module') {
    my ($code, $out) = enable_apache_security2();
    &print_command_result('a2enmod security2', $code, $out);
    if ($code == 0) {
        my ($tcode, $tout) = apache_configtest();
        if ($tcode != 0) {
            my ($dcode, $dout) = disable_apache_security2();
            print callout('bad', "Config test failed, so the security2 module was disabled again.");
            &print_command_result('Rollback: a2dismod security2', $dcode, $dout);
        }
        &print_command_result('Apache config test', $tcode, $tout);
        print_reload_form() if ($tcode == 0);
    }
} elsif ($action eq 'include') {
    my ($msg, $inc_backup) = ensure_custom_include();
    my ($code, $out) = apache_configtest();
    if ($code != 0 && restore_backup($p{modsecurity_conf}, $inc_backup)) {
        print callout('bad', "Config test failed. Reverted <span class='msm-path'>" .
                             &html_escape($p{modsecurity_conf}) . "</span>.");
    } else {
        print callout('ok', &html_escape($msg));
    }
    &print_command_result('Apache config test', $code, $out);
    print_reload_form() if ($code == 0);
} elsif ($action eq 'configtest') {
    my ($code, $out) = apache_configtest();
    print callout($code == 0 ? 'ok' : 'bad', $code == 0 ? "The Apache configuration is valid."
                                                       : "The Apache configuration has errors.");
    &print_command_result('Apache config test', $code, $out);
} else {
    sub action_card {
        my ($act, $ico, $title, $desc, $btn, $needs_edit, $kind) = @_;
        my $h = "<div class='msm-panel' style='display:flex;flex-direction:column;margin:0'>" .
                "<div class='msm-feature'><span class='msm-tile-ico'>" . icon($ico, 18) . "</span><span><b>" .
                &html_escape($title) . "</b><span>" . $desc . "</span></span></div><div style='flex:1'></div>";
        if (!$needs_edit || can_edit()) {
            $h .= "<form method='post' action='$act->[0]' class='msm-actions'>" . &ui_hidden('action', $act->[1]) .
                  msm_submit($btn, $kind || '') . "</form>";
        }
        return $h . "</div>\n";
    }
    print_readonly_notice();
    print "<div class='msm-h' style='margin-top:4px'>Apache</div><div class='msm-grid3'>\n";
    print action_card(['actions.cgi', 'configtest'], 'check', 'Test configuration',
        'Run <code>apachectl configtest</code> without changing anything.', 'Run test', 0, 'primary');
    print action_card(['actions.cgi', 'reload'], 'refresh', 'Test and reload',
        'Reload Apache only if the configuration test passes.', 'Test & reload', 1);
    print "</div>\n";

    print "<div class='msm-h'>Setup</div><div class='msm-grid3'>\n";
    print action_card(['actions.cgi', 'create_config'], 'file', 'Create modsecurity.conf',
        'Copy the recommended template if <code>modsecurity.conf</code> is missing.', 'Create config', 1);
    print action_card(['actions.cgi', 'enable_module'], 'package', 'Enable security2',
        'Run <code>a2enmod security2</code>; rolled back if the config test fails.', 'Enable module', 1);
    print action_card(['actions.cgi', 'include'], 'filter', 'Load custom exclusions',
        'Make sure the custom exclusions file is included by ModSecurity.', 'Include file', 1);
    print "</div>\n";

    print "<div class='msm-h'>Packages</div>\n";
    print "<div class='msm-wrap'><table class='msm-table'><tr><th>Package</th><th>Installed version</th></tr>";
    foreach my $pkg ('libapache2-mod-security2', 'modsecurity-crs') {
        my $v = package_version($pkg);
        print "<tr><td><span class='msm-path'>", &html_escape($pkg), "</span></td><td>",
              status_dot($v ? 'ok' : 'na'), &html_escape($v || 'Not installed'), "</td></tr>";
    }
    print "</table></div>\n";
    print "<div class='msm-grid3'>\n";
    print action_card(['updates.cgi', 'apt_update'], 'refresh', 'Refresh package lists',
        'Run <code>apt-get update</code>.', 'Run apt update', 1);
    print action_card(['updates.cgi', 'upgrade_modsecurity'], 'download', 'Upgrade ModSecurity & CRS',
        'Install available upgrades. Your changed config files are kept.', 'Upgrade packages', 1);
    print "</div>\n";
}

print_page_end();
&ui_print_footer($action ? "actions.cgi" : "", $action ? $text{'actions_title'} : $text{'index_return'},
                 $action ? ("", $text{'index_return'}) : ());
