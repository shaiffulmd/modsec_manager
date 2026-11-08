#!/usr/bin/perl
# Alert settings: e-mail / Telegram when blocked requests spike.
require './modsec-lib.pl';

&ui_print_header(undef, "Alerts", "");
print_nav('alerts.cgi', 'Get an e-mail or Telegram message when ModSecurity suddenly blocks many requests, for example during an attack.');

my %a = alert_settings();
my %p = paths();
my $cron_ok = -e $p{cron_file};
my ($recent) = recent_blocked($a{interval});
my $n = scalar(@$recent);

my $state = !$a{enabled} ? ['na', 'Off'] : $cron_ok ? ['ok', 'On'] : ['bad', 'On, but the cron job is missing'];
print "<div class='msm-cards'>",
      "<div class='msm-card'><div class='msm-card-label'>Alerts</div><div class='msm-card-value'>",
      status_dot($state->[0]), &html_escape($state->[1]), "</div><div class='msm-card-sub'>Checked every ",
      &html_escape($a{interval}), " minutes</div></div>",
      "<div class='msm-card'><div class='msm-card-label'>Blocked, last ", &html_escape($a{interval}), " min</div>",
      "<div class='msm-card-value'>", status_dot($n >= $a{threshold} ? 'bad' : 'ok'), $n,
      "</div><div class='msm-card-sub'>Alert at ", &html_escape($a{threshold}), " or more</div></div>",
      "</div>\n";
print_readonly_notice();

my $ro = can_edit() ? '' : ' disabled';
print "<form method='post' action='save_alerts.cgi'>";
print "<div class='msm-panel'><div class='msm-panel-title'>When to alert</div><div class='msm-panel-sub'>",
      "A cron job counts blocked requests in the audit log and sends at most one alert per quiet period.</div>\n";
print field_row("Alerts",
    "<div class='msm-choices' style='max-width:460px'>" .
    "<label class='msm-choice'><input type='radio' name='enabled' value='1'" . ($a{enabled} ? " checked" : "") . "$ro><span><b>On</b><small>Check on a schedule</small></span></label>" .
    "<label class='msm-choice'><input type='radio' name='enabled' value='0'" . (!$a{enabled} ? " checked" : "") . "$ro><span><b>Off</b><small>No cron job</small></span></label></div>");
print field_row("Check every",
    "<select name='interval'$ro>" .
    join('', map { "<option value='$_'" . ($a{interval} == $_ ? " selected" : "") . ">$_ minutes</option>" } (5, 10, 15, 30, 60)) .
    "</select>");
print field_row("Threshold",
    "<span class='msm-inline'><input name='threshold' size='6' inputmode='numeric' value='" . &html_escape($a{threshold}) . "'$ro> blocked requests in one interval</span>",
    "A busy server always sees some background scanning; set this above your normal level.");
print field_row("Quiet period",
    "<span class='msm-inline'><input name='cooldown' size='6' inputmode='numeric' value='" . &html_escape($a{cooldown}) . "'$ro> minutes after an alert</span>");
print "</div>\n";

print "<div class='msm-panel'><div class='msm-panel-title'>Where to send</div><div class='msm-panel-sub'>",
      "Use e-mail, Telegram or both.</div>\n";
print field_row(icon('file') . " E-mail",
    "<input type='email' name='email' size='40' value='" . &html_escape($a{email}) . "' placeholder='admin\@example.com'$ro>",
    "Sent through Webmin's mail settings (Read User Mail module) or the local sendmail.");
print field_row(icon('bell') . " Telegram bot token",
    "<input type='password' name='tg_token' size='40' autocomplete='off' placeholder='" .
    ($a{tg_token} ? "Saved &mdash; leave empty to keep" : "123456:ABC...") . "'$ro>" .
    ($a{tg_token} ? " <label class='msm-meta'><input type='checkbox' name='tg_clear' value='1'$ro>Remove saved token</label>" : ""),
    "Create a bot with \@BotFather. The token is stored in the module config, readable by root only, and never shown again.");
print field_row("Telegram chat ID",
    "<input name='tg_chat' size='20' value='" . &html_escape($a{tg_chat}) . "' placeholder='-1001234567890'$ro>",
    "Your user, group or channel ID (for example from \@userinfobot).");
print "</div>\n";
if (can_edit()) {
    print "<div class='msm-actions'>", msm_submit("Save settings", 'primary'),
          msm_submit("Save and send test alert", '', 'test', 1), "</div>";
}
print "</form>\n";
print "<p class='msm-meta' style='margin-top:14px'>Cron file: <span class='msm-path'>", &html_escape($p{cron_file}), "</span></p>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
