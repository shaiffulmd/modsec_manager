#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
&ui_print_header(undef, $text{'exclusions_title'}, "");
print_nav('exclusions.cgi');

my %p = paths();
ensure_custom_exclusions();
my $backup = backup_file($p{custom_exclusions});
write_text_file($p{custom_exclusions}, normalize_text($in{'rules'}), 0644);

my ($include_msg, $inc_backup) = ('', undef);
if ($in{'ensure_include'}) {
    ($include_msg, $inc_backup) = ensure_custom_include();
}

my ($code, $out) = apache_configtest();
if ($code != 0) {
    my @reverted;
    push(@reverted, $p{custom_exclusions}) if restore_backup($p{custom_exclusions}, $backup);
    push(@reverted, $p{modsecurity_conf})  if restore_backup($p{modsecurity_conf}, $inc_backup);
    print callout('bad', "Apache rejected the change. Restored " .
                         join(' and ', map { "<span class='msm-path'>" . &html_escape($_) . "</span>" } @reverted) . ".");
} else {
    print callout('ok', "Exclusions saved. Reload Apache to apply them.");
    print callout('info', &html_escape($include_msg)) if ($include_msg && $include_msg ne 'Already included');
    if (!custom_exclusions_included()) {
        print callout('warn', "The exclusions file is not loaded by ModSecurity, so these rules are not active.");
    }
}
print "<p class='msm-meta'>Backup: <span class='msm-path'>", &html_escape($backup || 'none'), "</span></p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();
&ui_print_footer("exclusions.cgi", "exclusions", "", $text{'index_return'});
