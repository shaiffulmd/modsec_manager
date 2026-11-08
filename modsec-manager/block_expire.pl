#!/usr/bin/perl
# Cron job: lift IP blocks whose end time has passed. Installed by the
# Blocked IPs page into /etc/cron.d while any block has an end time.

$no_acl_check++;
$ENV{'WEBMIN_CONFIG'} ||= "/etc/webmin";
$ENV{'WEBMIN_VAR'} ||= "/var/webmin";
if ($0 =~ m#^(.*)/[^/]+$#) {
    chdir($1);
}
require './modsec-lib.pl';

my $res = expire_blocks();
foreach my $r (grep { !$_->[2] } @$res) {
    print STDERR "modsec-manager: could not lift the block on $r->[0] at $r->[1]: $r->[3]\n";
}
exit(0);
