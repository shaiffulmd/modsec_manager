#!/usr/bin/perl
# Cron job: send an alert when blocked requests in the last interval reach the
# configured threshold. Installed by save_alerts.cgi into /etc/cron.d.

$no_acl_check++;
$ENV{'WEBMIN_CONFIG'} ||= "/etc/webmin";
$ENV{'WEBMIN_VAR'} ||= "/var/webmin";
if ($0 =~ m#^(.*)/[^/]+$#) {
    chdir($1);
}
require './modsec-lib.pl';

my %a = alert_settings();
exit(0) if (!$a{enabled});

my ($recent) = recent_blocked($a{interval});
my $n = scalar(@$recent);
exit(0) if ($n < $a{threshold});

# One alert per quiet period.
my $state = alert_state_file();
my $last = 0;
if (open(my $fh, '<', $state)) {
    $last = <$fh> || 0;
    chomp($last);
    close($fh);
}
exit(0) if ($last =~ /^\d+$/ && time() - $last < $a{cooldown} * 60);

my ($subject, $text, $html) = alert_message($recent, $a{interval});
my @res = send_alert($subject, $text, $html);
if (grep { $_->[1] } @res) {
    write_text_file($state, time() . "\n", 0600);
}
foreach my $r (grep { !$_->[1] } @res) {
    print STDERR "modsec-manager alert via $r->[0] failed: $r->[2]\n";
}
exit(0);
