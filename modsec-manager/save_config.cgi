#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
my ($label, $file) = editable_config_file($in{'target'});
&ui_print_header(undef, "Save config", "");
print_nav('config_editor.cgi');

my ($code, $out, $backup, $reverted) = save_file_with_configtest($file, $in{'content'});

if ($reverted) {
    print callout('bad', "Apache rejected the new configuration, so your changes to <span class='msm-path'>" .
                         &html_escape($file) . "</span> were <b>not</b> kept.");
} else {
    print callout('ok', "Saved <b>" . &html_escape($label) . "</b>. Reload Apache to apply it.");
}
print "<p class='msm-meta'>Backup: <span class='msm-path'>", &html_escape($backup || 'none (new file)'), "</span></p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();
&ui_print_footer("config_editor.cgi?target=" . &url_escape($in{'target'}), "config file", "", $text{'index_return'});
