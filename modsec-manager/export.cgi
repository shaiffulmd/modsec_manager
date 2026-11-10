#!/usr/bin/perl
# Downloads from the Logs page:
#   what=csv  the events matching the Logs page filters, as CSV;
#   what=zip  the raw log files (and rotated copies) as a ZIP with a
#             SHA-256 manifest. Raw audit logs can hold request bodies such
#             as passwords, so this needs edit access.
require './modsec-lib.pl';

&ReadParse();
my $what = defined($in{'what'}) ? $in{'what'} : '';
my ($source, $f) = logs_filters(\%in);
my $stamp = export_stamp();

if ($what eq 'csv') {
    my (undef, undef, $file, $err, $txs, $vhosts) = logs_select($source, $f);
    fail($err) if ($err);
    my $csv = events_csv($txs, $vhosts);
    &webmin_log("export", "csv", $file) if (defined(&webmin_log));
    binmode(STDOUT);
    print "Content-Type: text/csv; charset=utf-8\n",
          "Content-Disposition: attachment; filename=\"modsec-events-$stamp.csv\"\n",
          "Content-Length: ", length($csv), "\n\n", $csv;
} elsif ($what eq 'zip') {
    fail("Downloading the raw log files needs edit access to this module, because they can contain passwords " .
         "and cookies. You can still download the events as CSV.") if (!can_edit());
    my %p = paths();
    my $rotated = ($in{'rotated'} || 0) =~ /^([0-7])$/ ? $1 : 0;
    my @files = map { $_->[0] } log_files_with_rotated(audit_log_path(), $rotated);
    push(@files, map { $_->[0] } log_files_with_rotated($p{error_log}, $rotated)) if ($in{'error_log'});
    fail("No readable log files were found.") if (!@files);
    my $host = defined(&get_system_hostname) ? &get_system_hostname() : '';
    my $note = "ModSecurity logs exported by Webmin ModSecurity Manager\n" .
               "Server: $host\nExported: " . POSIX::strftime("%Y-%m-%d %H:%M:%S %z", localtime(time())) .
               "\nBy: " . ($remote_user || '-') . "\n";
    &webmin_log("export", "zip", join(' ', @files)) if (defined(&webmin_log));
    print "Content-Type: application/zip\n",
          "Content-Disposition: attachment; filename=\"modsec-logs-$stamp.zip\"\n\n";
    my $err = stream_zip(\@files, $note);
    print STDERR "modsec-manager export: $err\n" if ($err);
} else {
    fail("Unknown export type");
}
