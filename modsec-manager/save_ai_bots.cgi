#!/usr/bin/perl
# Save the AI bot settings: rebuild the rule file from the validated choices,
# test the config and keep the settings only if the test passes.
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();

my %known = map { $_->{token} => 1 } ai_bot_catalog();
my %sites = map { $_->{name} => 1 } apache_vhosts();
my @bots = grep { $known{$_} } split(/\0/, defined($in{'bot'}) ? $in{'bot'} : '');
my @allow = grep { $sites{$_} } split(/\0/, defined($in{'allow'}) ? $in{'allow'} : '');
my %s = ai_bot_settings();
$s{enabled} = $in{'enabled'} ? 1 : 0;
$s{mode} = ($in{'mode'} || '') eq 'log' ? 'log' : 'block';
$s{robots} = $in{'robots'} ? 1 : 0;
$s{bots} = \@bots;
$s{allow} = \@allow;
fail("Tick at least one AI bot, or turn the rules off.") if ($s{enabled} && !@bots);

&ui_print_header(undef, "AI bots", "");
print_nav('ai_bots.cgi');

my ($code, $out, $notes, $rules) = apply_ai_bots(%s);
if ($code == 0) {
    &lock_file("$module_config_directory/config");
    $config{'ai_bots_enabled'} = $s{enabled};
    $config{'ai_bots_mode'} = $s{mode};
    $config{'ai_bots_robots'} = $s{robots};
    $config{'ai_bots_list'} = join(',', @bots);
    $config{'ai_bots_allow_sites'} = join(',', @allow);
    &save_module_config();
    &unlock_file("$module_config_directory/config");
    &webmin_log("ai_bots") if (defined(&webmin_log));
    print callout('ok', !$s{enabled} ? "AI bot rules turned off. Reload Apache to apply."
        : ($s{mode} eq 'log' ? "AI bots will be logged" : "AI bots will be blocked") . " (" . scalar(@bots) .
          " selected" . (@allow ? ", " . scalar(@allow) . " site" . (@allow > 1 ? "s" : "") . " left open" : "") .
          "). Reload Apache to apply.");
} else {
    print callout('bad', "Apache rejected the configuration, so nothing was changed and the settings were not saved.");
}
print callout('info', join('<br>', map { &html_escape($_) } @$notes)) if (@$notes);
print "<details><summary>Rule file</summary><pre>", &html_escape($rules), "</pre></details>\n" if ($rules);
&print_command_result('Apache config test', $code, $out);
print_reload_form() if ($code == 0);

print_page_end();

&ui_print_footer("ai_bots.cgi", "AI bots", "", $text{'index_return'});
