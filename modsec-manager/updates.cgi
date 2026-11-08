#!/usr/bin/perl
# Package update actions, started from the Maintenance page.
require './modsec-lib.pl';

&ReadParse();
my $action = defined($in{'action'}) ? $in{'action'} : '';
if ($action eq '') {
    &redirect("actions.cgi");
    exit;
}
require_edit();
require_post();
&ui_print_header(undef, "Updates", "");
print_nav('actions.cgi');

if ($action eq 'apt_update') {
    my ($code, $out) = apt_update();
    print callout($code == 0 ? 'ok' : 'bad', $code == 0 ? "Package lists refreshed." : "apt-get update failed.");
    &print_command_result('apt-get update', $code, $out);
} elsif ($action eq 'upgrade_modsecurity') {
    my ($code, $out) = apt_upgrade_modsecurity();
    &print_command_result('Upgrade ModSecurity packages', $code, $out);
    my ($tcode, $tout) = apache_configtest();
    &print_command_result('Apache config test', $tcode, $tout);
    if ($tcode == 0) {
        print callout('info', "Reload Apache to load the upgraded module and rules.");
        print_reload_form();
    } else {
        print callout('bad', "The Apache config test failed after the upgrade. Apache was not reloaded; "
                             . "fix the reported error before reloading.");
    }
} else {
    fail("Unknown action");
}

print_page_end();
&ui_print_footer("actions.cgi", "maintenance", "", $text{'index_return'});
