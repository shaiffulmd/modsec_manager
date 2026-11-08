#!/usr/bin/perl
# Blocked IPs actions: block, unblock, and save settings (optionally testing
# the Cloudflare connection).
require './modsec-lib.pl';

&ReadParse();
require_edit();
require_post();
my $action = defined($in{'action'}) ? $in{'action'} : '';
my %names = block_target_names();

if ($action eq 'settings') {
    my @targets = grep { /^(?:cloudflare|modsec|ufw)$/ } split(/\0/, defined($in{'def_target'}) ? $in{'def_target'} : '');
    my $dur = defined($in{'duration'}) && $in{'duration'} =~ /^(?:1|6|24|168|720|0)$/ ? $in{'duration'} : fail("Invalid length");
    my @white = grep { $_ ne '' } split(/[\s,]+/, defined($in{'whitelist'}) ? $in{'whitelist'} : '');
    foreach my $w (@white) {
        fail("Not an address or range: $w") if (!cidr_parse($w));
    }
    my $acct = defined($in{'cf_account'}) ? $in{'cf_account'} : '';
    $acct =~ s/\s+//g;
    $acct = lc($acct);
    fail("A Cloudflare account ID is 32 letters and digits (0-9, a-f)") if ($acct ne '' && $acct !~ /^[0-9a-f]{32}$/);
    my $token = defined($in{'cf_token'}) ? $in{'cf_token'} : '';
    $token =~ s/\s+//g;
    fail("That does not look like a Cloudflare API token") if ($token ne '' && $token !~ /^[A-Za-z0-9_-]{30,}$/);
    my $mode = ($in{'cf_mode'} || '') eq 'managed_challenge' ? 'managed_challenge' : 'block';

    &lock_file("$module_config_directory/config");
    $config{'block_targets'} = join(',', @targets);
    $config{'block_duration'} = $dur;
    $config{'block_whitelist'} = join(',', @white);
    $config{'block_cf_mode'} = $mode;
    $config{'block_cf_token'} = '' if ($in{'cf_clear'});
    $config{'block_cf_token'} = $token if ($token ne '');
    $config{'block_cf_account'} = $acct;
    my ($found, $found_msg);
    if ($config{'block_cf_token'} && $acct eq '') {
        my %s = block_settings();
        ($found, $found_msg) = cf_detect_account(%s, cf_token => $config{'block_cf_token'});
        $config{'block_cf_account'} = $found if ($found);
    }
    &save_module_config();
    &unlock_file("$module_config_directory/config");
    chmod(0600, "$module_config_directory/config");
    # Log the action only: %in holds the API token.
    &webmin_log("block_settings") if (defined(&webmin_log));

    if (!$in{'test'} && !$found_msg) {
        &redirect("blocks.cgi");
        exit;
    }
    &ui_print_header(undef, "Blocked IPs", "");
    print_nav('blocks.cgi');
    print callout($found ? 'ok' : 'warn', &html_escape($found_msg)) if ($found_msg);
    if ($in{'test'}) {
        my %s = block_settings();
        my %bad = block_target_problems(%s);
        if ($bad{cloudflare}) {
            print callout('bad', &html_escape($bad{cloudflare}));
        } else {
            my ($ok, $msg) = cf_test_connection(%s);
            print callout($ok ? 'ok' : 'bad', &html_escape($msg) . ($ok ? " Blocking also needs the <b>Edit</b> permission; " .
                "the first block shows whether it has it." : ""));
        }
    }
    print callout('info', "Settings saved.");
    print "<p><a class='msm-btn' href='blocks.cgi'>Back to Blocked IPs</a></p>\n";
    print_page_end();
    &ui_print_footer("blocks.cgi", "Blocked IPs", "", $text{'index_return'});
    exit;
}

&ui_print_header(undef, "Blocked IPs", "");
print_nav('blocks.cgi');

if ($action eq 'block') {
    my %s = block_settings();
    my $ip = defined($in{'ip'}) ? $in{'ip'} : '';
    $ip =~ s/^\s+|\s+$//g;
    my @targets = grep { /^(?:cloudflare|modsec|ufw)$/ } split(/\0/, defined($in{'target'}) ? $in{'target'} : '');
    my $hours = defined($in{'hours'}) && $in{'hours'} =~ /^(?:1|6|24|168|720|0)$/ ? $in{'hours'} : 24;
    my $why = block_refusal($ip, %s);
    if ($why) {
        print callout('bad', "<b>Not blocked.</b> " . &html_escape($why));
    } elsif (!@targets) {
        print callout('bad', "<b>Not blocked.</b> Tick at least one place to block at.");
    } else {
        my ($ok, $res) = block_ip($ip, $in{'reason'}, $hours, \@targets, $remote_user);
        my $c = ip_canonical($ip);
        print callout($ok ? 'ok' : 'bad', $ok ? "<b>" . &html_escape($c) . "</b> is blocked" .
            ($hours ? " until " . &html_escape(fmt_time(time() + $hours * 3600)) : " until you remove it") . "."
            : "<b>" . &html_escape($c) . "</b> could not be blocked anywhere.");
        print_block_results(map { [$_->[0], $_->[1], $_->[2]] } @$res);
    }
} elsif ($action eq 'unblock') {
    my $ip = ip_canonical($in{'ip'}) || fail("Invalid address");
    my $res = unblock_ips([$ip]);
    my $left = grep { $_->{ip} eq $ip } @{read_blocks()};
    print callout($left ? 'warn' : 'ok', $left ? "<b>" . &html_escape($ip) . "</b> is still blocked in some places; see below."
                                               : "<b>" . &html_escape($ip) . "</b> is no longer blocked.");
    print_block_results(map { [$_->[1], $_->[2], $_->[3]] } @$res);
} else {
    fail("Unknown action");
}
print "<p><a class='msm-btn' href='blocks.cgi'>Back to Blocked IPs</a></p>\n";
print_page_end();
&ui_print_footer("blocks.cgi", "Blocked IPs", "logs.cgi", "logs");

sub print_block_results {
    foreach my $r (@_) {
        print "<div class='msm-ins'><div class='msm-ins-main'>", status_dot($r->[1] ? 'ok' : 'bad'), "<b>",
              &html_escape($names{$r->[0]} || $r->[0]), "</b><div class='msm-ins-sub' style='white-space:pre-wrap'>",
              &html_escape($r->[2]), "</div></div></div>\n";
    }
}
