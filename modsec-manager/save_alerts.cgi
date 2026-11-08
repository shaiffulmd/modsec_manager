#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();

my $interval = $in{'interval'} =~ /^(5|10|15|30|60)$/ ? $1 : fail("Invalid interval");
fail("Threshold must be a whole number of 1 or more") if ($in{'threshold'} !~ /^\d{1,6}$/ || $in{'threshold'} < 1);
fail("Quiet period must be a whole number of minutes") if ($in{'cooldown'} !~ /^\d{1,5}$/);
my $email = $in{'email'};
$email =~ s/^\s+|\s+$//g;
fail("Invalid e-mail address") if ($email ne '' && $email !~ /^[^\s@,;<>"]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/);
my $chat = $in{'tg_chat'};
$chat =~ s/\s+//g;
fail("Telegram chat ID must be a number or \@channelname") if ($chat ne '' && $chat !~ /^(?:-?\d+|@[A-Za-z0-9_]{5,})$/);
my $token = $in{'tg_token'};
$token =~ s/\s+//g;
fail("That does not look like a Telegram bot token") if ($token ne '' && $token !~ /^\d+:[A-Za-z0-9_-]{20,}$/);
my $eff_token = $in{'tg_clear'} ? '' : $token ne '' ? $token : ($config{'alert_telegram_token'} || '');
fail("To turn alerts on, enter an e-mail address or a Telegram bot token and chat ID")
    if ($in{'enabled'} && $email eq '' && !($eff_token ne '' && $chat ne ''));

&lock_file("$module_config_directory/config");
$config{'alert_enabled'} = $in{'enabled'} ? 1 : 0;
$config{'alert_interval'} = $interval;
$config{'alert_threshold'} = $in{'threshold'};
$config{'alert_cooldown'} = $in{'cooldown'};
$config{'alert_email'} = $email;
$config{'alert_telegram_chat'} = $chat;
$config{'alert_telegram_token'} = '' if ($in{'tg_clear'});
$config{'alert_telegram_token'} = $token if ($token ne '');
&save_module_config();
&unlock_file("$module_config_directory/config");
chmod(0600, "$module_config_directory/config");

my %a = alert_settings();
write_alert_cron($a{enabled}, $a{interval});
# Log the action only: %in holds the Telegram token.
&webmin_log("alerts") if (defined(&webmin_log));

if (!$in{'test'}) {
    &redirect("alerts.cgi");
    exit;
}

&ui_print_header(undef, "Alerts", "");
print_nav('alerts.cgi');
my ($recent) = recent_blocked($a{interval});
my ($subject, $body) = alert_message($recent, $a{interval});
my @res = send_alert("[TEST] $subject", $body);
if (!@res) {
    print "<div class='msm-alert'><div class='msm-alert-text'>Settings saved, but no e-mail address or ",
          "Telegram bot is configured, so nothing was sent.</div></div>\n";
}
foreach my $r (@res) {
    print_command_result("Test via $r->[0]", $r->[1] ? 0 : 1, $r->[2]);
}
print "<div class='msm-h'>Message</div><pre>", &html_escape("$subject\n\n$body"), "</pre>\n";
print_page_end();
&ui_print_footer("alerts.cgi", "alerts", "", $text{'index_return'});
