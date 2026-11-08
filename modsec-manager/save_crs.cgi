#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
&ui_print_header(undef, "Protection", "");
print_nav('mode.cgi');

my ($code, $out, $backup, $reverted) = save_crs_settings($in{'paranoia'}, $in{'inbound'}, $in{'outbound'});

if ($reverted) {
    print callout('bad', "Apache rejected the change, so the CRS settings were not changed.");
} else {
    print callout('ok', "Saved: paranoia level <b>" . &html_escape($in{'paranoia'}) . "</b>, inbound threshold <b>" .
                        &html_escape($in{'inbound'}) . "</b>, outbound threshold <b>" . &html_escape($in{'outbound'}) .
                        "</b>. Reload Apache to apply.");
}
print "<p class='msm-meta'>Backup: ", &html_escape($backup || 'none'), "</p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();

&ui_print_footer("mode.cgi", "protection", "", $text{'index_return'});
