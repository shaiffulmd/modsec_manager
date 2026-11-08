#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
my $file = $in{'file'};
validate_managed_rule_file($file, 1);
&ui_print_header(undef, "Save rule file", "");
print_nav('rules.cgi');

my ($code, $out, $backup, $reverted) = save_file_with_configtest($file, $in{'content'});

if ($reverted) {
    print callout('bad', "Apache rejected the change. <span class='msm-path'>" . &html_escape($file) .
                         "</span> was restored to its previous version.");
} else {
    print callout('ok', "Saved <span class='msm-path'>" . &html_escape($file) . "</span>. Reload Apache to apply it.");
}
print "<p class='msm-meta'>Backup: <span class='msm-path'>", &html_escape($backup || 'none'), "</span></p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();
&ui_print_footer("rules.cgi", "rules", "", $text{'index_return'});
