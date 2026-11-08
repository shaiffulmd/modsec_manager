#!/usr/bin/perl
# Append a builder-generated exclusion. The rule text is rebuilt from the
# validated fields here; no config text is accepted from the browser.
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
my ($c, $err) = clean_exclusion_input(map { $_ => $in{$_} } ('rule', 'host', 'path', 'match', 'target', 'scope'));
fail($err) if ($err);
&ui_print_header(undef, "Add exclusion", "");
print_nav('exclusions.cgi');

my $id = next_custom_rule_id();
my ($sec, $min, $hour, $mday, $mon, $year) = localtime(time());
my $note = sprintf("added %04d-%02d-%02d via Webmin", $year + 1900, $mon + 1, $mday);
my $snippet = build_exclusion($c, $id, $note);
my ($code, $out, $backup, $reverted, $inc_msg) = append_exclusion($snippet, $in{'ensure_include'});

if ($code == 0) {
    print callout('ok', "Added exclusion <b>id:$id</b>: " . &html_escape(describe_exclusion($c)) . ". Reload Apache to activate it.");
} else {
    print callout('bad', "Apache rejected the configuration, so the exclusion was not kept.");
}
print callout('info', &html_escape($inc_msg)) if ($inc_msg && $inc_msg ne 'Already included');
print "<div class='msm-result'><div class='msm-result-head'><span>Added rule</span></div><pre>", &html_escape($snippet), "</pre></div>\n";
print "<p class='msm-meta'>Backup: ", &html_escape($backup || 'none (new file)'), "</p>\n";
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();

&ui_print_footer("exclusions.cgi", "exclusions", "logs.cgi", "logs");
