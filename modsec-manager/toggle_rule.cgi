#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
my $from = $in{'file'};
my $to = toggle_rule_file($from, $in{'enable'});
&ui_print_header(undef, "Toggle rule file", "");
print_nav('rules.cgi');

my ($code, $out) = apache_configtest();
if ($code != 0) {
    revert_rule_toggle($from, $to);
    print callout('bad', "Apache rejected the change, so the file was renamed back.");
} else {
    print callout('ok', ($in{'enable'} ? "Enabled" : "Disabled") . " <span class='msm-path'>" .
                        &html_escape(File::Basename::basename($from)) . "</span>. Reload Apache to apply it.");
}
print "<p class='msm-meta'><span class='msm-path'>", &html_escape($from), "</span> &rarr; <span class='msm-path'>",
      &html_escape($to), "</span></p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();
&ui_print_footer("rules.cgi", "rules", "", $text{'index_return'});
