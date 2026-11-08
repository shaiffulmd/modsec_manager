#!/usr/bin/perl
# Preview the alert e-mail with current log data, without sending anything.
require './modsec-lib.pl';

&ui_print_header(undef, "Alert preview", "");
print_nav('alerts.cgi', 'This is what an alert looks like with the blocked requests of the last check interval. Nothing is sent.');
my %a = alert_settings();
my ($recent) = recent_blocked($a{interval});
my ($subject, $text, $html) = alert_message($recent, $a{interval});
print callout('info', "Only " . scalar(@$recent) . " blocked requests in the last $a{interval} minutes, below the alert "
                      . "threshold of " . &html_escape($a{threshold}) . ". A real alert would not be sent now.")
    if (@$recent < $a{threshold});
print_email_preview($subject, $text, $html);

print_page_end();
&ui_print_footer("alerts.cgi", "alerts", "", $text{'index_return'});
