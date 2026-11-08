#!/usr/bin/perl
# Blocked IPs: block attacker addresses at Cloudflare, in ModSecurity and in
# ufw, list current blocks and lift them, and the blocking settings.
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Blocked IPs", "");
print_nav('blocks.cgi', 'Block attacker addresses at Cloudflare, in ModSecurity and in the server firewall. ' .
    'Blocks can end by themselves.');

my %s = block_settings();
my %bad = block_target_problems(%s);
my %names = block_target_names();
my $list = read_blocks();
my $now = time();
my $soon = grep { $_->{expires} && $_->{expires} - $now < 86400 } @$list;
my %count;
foreach my $b (@$list) { $count{$_}++ foreach (keys %{$b->{targets}}); }

# --- Summary cards ------------------------------------------------------------

my @cards = (
    ['Blocked now', @$list ? 'ok' : 'na', scalar(@$list),
        join(', ', map { "$names{$_} $count{$_}" } grep { $count{$_} } qw(cloudflare modsec ufw)) || 'No addresses blocked'],
    ['Ending within a day', $soon ? 'ok' : 'na', $soon, 'Lifted automatically'],
    ['Cloudflare', $bad{cloudflare} ? 'na' : 'ok', $bad{cloudflare} ? 'Not set up' : 'API token saved',
        $s{cf_mode} eq 'block' ? 'Mode: block' : 'Mode: managed challenge'],
    ['ufw firewall', $bad{ufw} ? 'na' : 'ok', $bad{ufw} ? 'Not installed' : 'Available', 'Direct connections only'],
);
print "<div class='msm-cards'>\n";
foreach my $c (@cards) {
    print "<div class='msm-card'><div class='msm-card-label'>", &html_escape($c->[0]), "</div>",
          "<div class='msm-card-value'>", status_dot($c->[1]), &html_escape($c->[2]), "</div>",
          "<div class='msm-card-sub'>", &html_escape($c->[3]), "</div></div>\n";
}
print "</div>\n";
print_readonly_notice();

# --- Block an address -----------------------------------------------------------

my %durations = (1 => '1 hour', 6 => '6 hours', 24 => '1 day', 168 => '7 days', 720 => '30 days', 0 => 'Until removed');
my %help = (cloudflare => 'Refused at the edge for every proxied site in the account. No load on this server.',
            modsec => 'Works for all traffic, proxied or direct. Apache is reloaded after each change.',
            ufw => 'All ports, but only for direct connections: traffic through Cloudflare comes from Cloudflare\'s addresses.');
if (can_edit()) {
    my $ip = defined($in{'ip'}) ? $in{'ip'} : '';
    $ip =~ s/^\s+|\s+$//g;
    if ($ip ne '') {
        my $why = block_refusal($ip, %s);
        print callout('bad', "<b>This address cannot be blocked.</b> " . &html_escape($why)) if ($why);
    }
    my %def = map { $_ => 1 } @{$s{targets}};
    print "<form method='post' action='save_blocks.cgi'>", &ui_hidden('action', 'block');
    print "<div class='msm-panel'><div class='msm-panel-title'>Block an address</div><div class='msm-panel-sub'>",
          "Cloudflare, private and this server's addresses are always refused.</div>\n";
    print field_row("Address", "<input name='ip' size='40' value='" . &html_escape($ip) .
        "' placeholder='203.0.113.9 or 2001:db8::1' autocomplete='off' spellcheck='false'>");
    print field_row("Reason", "<input name='reason' size='60' maxlength='200' value='" .
        &html_escape(defined($in{'reason'}) ? $in{'reason'} : '') . "' placeholder='Scanner, 40 SQL injection attempts'>",
        "Saved with the block and in the Cloudflare rule's notes.");
    print field_row("For how long", "<select name='hours'>" .
        join('', map { "<option value='$_'" . ($_ == $s{duration} ? " selected" : "") . ">$durations{$_}</option>" }
             (1, 6, 24, 168, 720, 0)) . "</select>");
    print field_row("Block at", "<div class='msm-choices'>" . join('', map {
        my $t = $_;
        "<label class='msm-choice'><input type='checkbox' name='target' value='$t'" .
        ($def{$t} && !$bad{$t} ? " checked" : "") . ($bad{$t} ? " disabled" : "") . "><span><b>" .
        &html_escape($names{$t}) . "</b><small>" . &html_escape($bad{$t} || $help{$t}) . "</small></span></label>"
    } qw(cloudflare modsec ufw)) . "</div>");
    print "</div>\n<div class='msm-actions'>", msm_submit("Block address", 'danger'), "</div></form>\n";
}

# --- Current blocks ---------------------------------------------------------------

print "<div class='msm-h'>Blocked addresses</div>\n";
if (@$list) {
    print "<div class='msm-wrap'><table class='msm-table'>\n<tr><th>Address</th><th>Reason</th><th>Blocked at</th>",
          "<th>Added</th><th>Ends</th>", (can_edit() ? "<th></th>" : ""), "</tr>\n";
    foreach my $b (sort { $b->{added} <=> $a->{added} } @$list) {
        print "<tr><td><a href='logs.cgi?ip=", &url_escape($b->{ip}), "'><b>", &html_escape($b->{ip}), "</b></a></td>",
              "<td>", &html_escape($b->{reason} || '-'), ($b->{by} ? "<div class='msm-meta'>by " . &html_escape($b->{by}) . "</div>" : ""),
              "</td><td>", join(' ', map { "<span class='msm-badge'>" . &html_escape($names{$_}) . "</span>" }
                                     grep { $b->{targets}{$_} } qw(cloudflare modsec ufw)),
              "</td><td>", &html_escape(fmt_time($b->{added})), "</td><td>",
              ($b->{expires} ? &html_escape(fmt_time($b->{expires})) : "Until removed"), "</td>";
        if (can_edit()) {
            print "<td><form method='post' action='save_blocks.cgi' style='margin:0'>", &ui_hidden('action', 'unblock'),
                  &ui_hidden('ip', $b->{ip}), msm_submit('Unblock'), "</form></td>";
        }
        print "</tr>\n";
    }
    print "</table></div>\n";
} else {
    print "<div class='msm-panel'><div class='msm-empty'>No addresses are blocked. Use the Block button on ",
          "<a href='logs.cgi'>Logs</a> (Likely attackers) or the form above.</div></div>\n";
}

# --- Settings -------------------------------------------------------------------

my $ro = can_edit() ? '' : ' disabled';
print "<form method='post' action='save_blocks.cgi'>", &ui_hidden('action', 'settings');
print "<div class='msm-panel' style='margin-top:18px'><div class='msm-panel-title'>Settings</div><div class='msm-panel-sub'>",
      "Defaults for new blocks, and the Cloudflare API connection.</div>\n";
print field_row("Default places", join(' ', map { my $t = $_;
    "<label class='msm-inline' style='margin-right:14px'><input type='checkbox' name='def_target' value='$t'" .
    ((grep { $_ eq $t } @{$s{targets}}) ? " checked" : "") . "$ro> " . &html_escape($names{$t}) . "</label>" } qw(cloudflare modsec ufw)));
print field_row("Default length", "<select name='duration'$ro>" .
    join('', map { "<option value='$_'" . ($_ == $s{duration} ? " selected" : "") . ">$durations{$_}</option>" }
         (1, 6, 24, 168, 720, 0)) . "</select>");
print field_row("Never block", "<textarea name='whitelist' rows='3' cols='50' spellcheck='false'$ro>" .
    &html_escape(join("\n", @{$s{whitelist}})) . "</textarea>",
    "Addresses or ranges (one per line), such as your office or monitoring service.");
print field_row(icon('cloud') . " Cloudflare API token",
    "<input type='password' name='cf_token' size='44' autocomplete='off' placeholder='" .
    ($s{cf_token} ? "Saved &mdash; leave empty to keep" : "API token") . "'$ro>" .
    ($s{cf_token} ? " <label class='msm-meta'><input type='checkbox' name='cf_clear' value='1'$ro>Remove saved token</label>" : ""),
    "Create it in Cloudflare under My Profile &gt; API Tokens &gt; Create Custom Token, with the permission " .
    "<b>Account &gt; Account Firewall Access Rules &gt; Edit</b> for your account. Stored in the module config " .
    "(root only) and never shown again.");
print field_row("Cloudflare account ID",
    "<input name='cf_account' size='36' value='" . &html_escape($s{cf_account}) . "' placeholder='Found automatically if left empty' spellcheck='false'$ro>",
    "Shown on the right of any domain's Overview page in the Cloudflare dashboard.");
print field_row("At Cloudflare",
    "<div class='msm-choices' style='max-width:460px'>" .
    "<label class='msm-choice'><input type='radio' name='cf_mode' value='block'" . ($s{cf_mode} eq 'block' ? " checked" : "") .
    "$ro><span><b>Block</b><small>Refuse every request</small></span></label>" .
    "<label class='msm-choice'><input type='radio' name='cf_mode' value='managed_challenge'" .
    ($s{cf_mode} eq 'managed_challenge' ? " checked" : "") . "$ro><span><b>Managed challenge</b>" .
    "<small>A person can still get through</small></span></label></div>");
print "</div>\n";
if (can_edit()) {
    print "<div class='msm-actions'>", msm_submit("Save settings", 'primary'),
          msm_submit("Save and test Cloudflare", '', 'test', 1), "</div>\n";
}
print "</form>\n";
print "<p class='msm-meta' style='margin-top:14px'>Before blocking at Cloudflare, check the <a href='cloudflare.cgi'>Cloudflare</a> ",
      "page: ModSecurity must log visitors' real addresses. ModSecurity list: <span class='msm-path'>",
      &html_escape($s{data_file}), "</span>.</p>\n";

print_page_end();

&ui_print_footer("", $text{'index_return'});
