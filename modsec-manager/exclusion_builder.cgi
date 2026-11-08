#!/usr/bin/perl
# Build a scoped exclusion (rule x site x path x request part) from log data.
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Exclusion builder", "");
print_nav('exclusions.cgi', 'Build an exclusion for a confirmed false positive. Scope it as narrowly as you can: '.
                            'one site, one path, and ideally only the request field that triggered the rule.');

my $history = ($in{'history'} || 0) =~ /^([0-7])$/ ? $1 : 0;
my ($raw, $txs) = read_recent_log('audit', $history);
my $rule = defined($in{'rule'}) ? $in{'rule'} : '';
$rule =~ s/\D//g;
my $det = $rule ne '' ? rule_log_details($txs, $rule) : { hosts => [], paths => [], targets => [], count => 0 };

my $scope = ($in{'scope'} || '') eq 'rule' ? 'rule' : ($in{'scope'} || '') eq 'target' ? 'target' : '';
# Default to the narrowest sensible scope: one request part if the log shows one.
if ($scope eq '') {
    $scope = @{$det->{targets}} ? 'target' : 'rule';
}
my %v = (
    rule   => $rule,
    host   => defined($in{'host'}) ? $in{'host'} : '',
    path   => defined($in{'path'}) ? $in{'path'} : '',
    match  => ($in{'match'} || 'begins'),
    target => defined($in{'target'}) ? $in{'target'} : (@{$det->{targets}} ? $det->{targets}[0][0] : ''),
    scope  => $scope,
);

print_readonly_notice();

# --- Form -------------------------------------------------------------------

sub datalist {
    my ($id, $rows) = @_;
    return "<datalist id='$id'>" .
           join('', map { "<option value='" . &html_escape($_->[0]) . "'>" . &html_escape("$_->[1] hits") . "</option>" } @$rows) .
           "</datalist>";
}
sub hint_text {
    my ($rows) = @_;
    return '' if (!@$rows);
    my @top = @$rows > 4 ? @$rows[0 .. 3] : @$rows;
    return "Seen in the log: " . join(', ', map { &html_escape($_->[0]) . " (" . $_->[1] . ")" } @top) .
           (@$rows > 4 ? ", ..." : "") . ". ";
}

print "<form method='get' action='exclusion_builder.cgi'><div class='msm-panel'>";
print &ui_hidden('history', $history) if ($history);
print field_row("<span class='msm-badge'>1</span> Rule",
    "<input name='rule' size='10' inputmode='numeric' placeholder='942100' value='" . &html_escape($v{rule}) . "'>" .
    ($det->{msg} ? " <span class='msm-meta'>" . &html_escape($det->{msg}) . "</span>" : ""),
    $rule ne '' ? "$det->{count} requests in the log window triggered this rule." : "The rule ID from the Logs page.");
print field_row("<span class='msm-badge'>2</span> Site",
    "<input name='host' list='msm-hosts' size='36' placeholder='All sites' value='" . &html_escape($v{host}) . "'>" .
    datalist('msm-hosts', $det->{hosts}),
    hint_text($det->{hosts}) . "Leave empty to apply on every site on this server.");
print field_row("<span class='msm-badge'>3</span> Path",
    "<span class='msm-inline'><input name='path' list='msm-paths' size='36' placeholder='All paths' value='" .
    &html_escape($v{path}) . "'>" . datalist('msm-paths', $det->{paths}) .
    "<label><input type='radio' name='match' value='begins'" . ($v{match} ne 'exact' ? " checked" : "") . ">starts with</label>" .
    "<label><input type='radio' name='match' value='exact'" . ($v{match} eq 'exact' ? " checked" : "") . ">exactly</label></span>",
    hint_text($det->{paths}) . "Leave empty for every path.");
print field_row("<span class='msm-badge'>4</span> What to exclude",
    "<div class='msm-choices'>" .
    "<label class='msm-choice'><input type='radio' name='scope' value='target'" . ($v{scope} eq 'target' ? " checked" : "") .
    "><span><b>One request field</b><small>Safest. The rule keeps checking everything else.</small>" .
    "<input name='target' list='msm-targets' size='26' placeholder='ARGS:comment' style='margin-top:8px' value='" .
    &html_escape($v{target}) . "'>" . datalist('msm-targets', $det->{targets}) . "</span></label>" .
    "<label class='msm-choice'><input type='radio' name='scope' value='rule'" . ($v{scope} eq 'rule' ? " checked" : "") .
    "><span><b>The whole rule</b><small>Turns the rule off completely within the site and path above.</small></span></label></div>",
    hint_text($det->{targets}));
print "<div class='msm-actions'>", msm_submit("Preview exclusion", 'primary'), "</div></div></form>\n";

# --- Preview ----------------------------------------------------------------

if ($rule ne '' || defined($in{'host'})) {
    my ($c, $err) = clean_exclusion_input(%v);
    if ($err) {
        print callout('bad', &html_escape($err));
    } else {
        my $id = next_custom_rule_id();
        my $snippet = build_exclusion($c, $id);
        my %pp = paths();
        print "<div class='msm-panel'><div class='msm-panel-title'>Preview</div>",
              "<div class='msm-panel-sub'>This will <b>", &html_escape(describe_exclusion($c)), "</b>.</div>\n";
        if ($c->{host} eq '' && $c->{path} eq '' && $c->{target} eq '') {
            print callout('bad', "This switches rule <b>" . &html_escape($c->{rule}) . "</b> off for the whole server. "
                                 . "Prefer limiting it to a site, a path or a request field.");
        } elsif ($c->{target} eq '') {
            print callout('warn', "The whole rule is turned off in this scope. Excluding only the request field "
                                  . "that triggers it keeps the rest of the protection.");
        } else {
            print callout('ok', "Narrow exclusion: everything else this rule checks stays protected.");
        }
        print "<div class='msm-result'><div class='msm-result-head'><span>", icon('file'), " ",
              "<span class='msm-path'>", &html_escape($pp{custom_exclusions}), "</span></span>",
              "<span class='msm-result-code'>appended</span></div><pre>", &html_escape($snippet), "</pre></div>\n";
        if (can_edit()) {
            print "<form method='post' action='save_exclusion_rule.cgi' class='msm-actions'>";
            print &ui_hidden($_, $c->{$_}) foreach ('rule', 'host', 'path', 'match', 'target');
            print &ui_hidden('scope', $c->{target} ne '' ? 'target' : 'rule');
            print msm_submit("Add exclusion and test config", 'primary'),
                  "<label><input type='checkbox' name='ensure_include' value='1' checked>Make sure ModSecurity loads the exclusions file</label></form>\n";
        }
        print "</div>\n";
    }
}

print_page_end();

&ui_print_footer("exclusions.cgi", "exclusions", "", $text{'index_return'});
