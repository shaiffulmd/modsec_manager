#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
fail("Select an enforcement mode") if (!$in{'mode'});
&ui_print_header(undef, "Protection", "");
print_nav('mode.cgi');

my %p = paths();
my $backup = set_engine_mode($in{'mode'});
my ($code, $out) = apache_configtest();

if ($code != 0 && restore_backup($p{modsecurity_conf}, $backup)) {
    print callout('bad', "Apache rejected the change, so <span class='msm-path'>" .
                         &html_escape($p{modsecurity_conf}) . "</span> was restored.");
} else {
    print callout('ok', "SecRuleEngine set to <b>" . &html_escape(current_engine_mode()) .
                        "</b>. Reload Apache for the change to take effect.");
}
print "<p class='msm-meta'>Backup: <span class='msm-path'>", &html_escape($backup || 'none'), "</span></p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();
&ui_print_footer("mode.cgi", "protection", "", $text{'index_return'});
