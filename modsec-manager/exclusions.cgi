#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, $text{'exclusions_title'}, "");
print_nav('exclusions.cgi', 'Silence confirmed false positives. Prefer the builder: it scopes each exclusion '.
                            'to a site, a path and a single request field.');

my %p = paths();
if (!-e $p{custom_exclusions} && can_edit()) {
    ensure_custom_exclusions();
}
fail("Exclusions file exists but is not readable: $p{custom_exclusions}")
    if (-e $p{custom_exclusions} && !-r $p{custom_exclusions});
my $data = read_text_file($p{custom_exclusions});
my $count = () = $data =~ /^[ \t]*[^#\s].*\bctl:ruleRemove/mg;
my $included = custom_exclusions_included();

# Pre-fill a runtime exclusion (links from older versions of the log page).
my $added = '';
if (can_edit() && defined($in{'add_id'}) && $in{'add_id'} =~ /^\d{1,9}$/) {
    my $rid = next_custom_rule_id();
    my $uri = defined($in{'add_uri'}) ? $in{'add_uri'} : '';
    $uri =~ s/[\s"\\]//g;
    $data = normalize_text($data);
    if ($uri ne '' && $uri =~ m#^/#) {
        $data .= "\n# Disable rule $in{'add_id'} for $uri\n".
                 "SecRule REQUEST_FILENAME \"\@beginsWith $uri\" \\\n".
                 "    \"id:$rid,phase:1,pass,nolog,ctl:ruleRemoveById=$in{'add_id'}\"\n";
    } else {
        $data .= "\n# Disable rule $in{'add_id'} everywhere\n".
                 "SecAction \"id:$rid,phase:1,pass,nolog,ctl:ruleRemoveById=$in{'add_id'}\"\n";
    }
    $added = $in{'add_id'};
}

print "<div class='msm-cards'>",
      "<div class='msm-card'><div class='msm-card-label'>Exclusions in file</div><div class='msm-card-value'>",
      $count, "</div><div class='msm-card-sub'>Active <code>ctl:ruleRemove&hellip;</code> rules</div></div>",
      "<div class='msm-card'><div class='msm-card-label'>Loaded by ModSecurity</div><div class='msm-card-value'>",
      status_dot($included ? 'ok' : 'warn'), ($included ? 'Yes' : 'No'), "</div><div class='msm-card-sub'>",
      &html_escape($included || 'Not included anywhere'), "</div></div>",
      "</div>\n";
if (can_edit()) {
    print callout('info', "<b>Exclusion builder</b> &mdash; pick a rule from the logs and limit it to one site, path or field. "
                          . "It previews the rule and tests the config before saving.",
                  "<a class='msm-btn msm-btn-primary' href='exclusion_builder.cgi'>" . icon('wand', 15) . "Open builder</a>");
}
print callout('info', "An exclusion for rule <b>" . &html_escape($added) . "</b> was added to the editor below. "
                      . "Review it, then save.") if ($added ne '');
print_readonly_notice();

print "<div class='msm-panel'><div class='msm-panel-head'><div><div class='msm-panel-title'>Custom exclusions file</div>",
      "<div class='msm-panel-sub'><span class='msm-path'>", &html_escape($p{custom_exclusions}), "</span>",
      (-e $p{custom_exclusions} ? "" : " &middot; not created yet"), "</div></div></div>\n";
print "<form method='post' action='save_exclusions.cgi'>";
print text_editor('rules', $data, 22);
if (can_edit()) {
    print "<div class='msm-actions'>", msm_submit("Save and test", 'primary'),
          "<label><input type='checkbox' name='ensure_include' value='1' checked>Make sure ModSecurity loads this file</label></div>\n";
}
print "</form></div>\n";

print <<'HELP';
<details class='msm-panel'><summary>How exclusions work here</summary>
<p>On Ubuntu this file is normally loaded <b>before</b> the OWASP CRS rules
(<code>IncludeOptional /etc/modsecurity/*.conf</code> runs before the CRS <code>*.load</code> include).
<code>SecRuleRemoveById</code> and <code>SecRuleUpdateTargetById</code> only affect rules that are
already loaded, so they do nothing here. Use runtime <code>ctl:</code> exclusions, each with a
unique rule id (1000000&ndash;1099999 is free for local rules):</p>
<pre>
# Disable rule 942100 only for one path
SecRule REQUEST_FILENAME "@beginsWith /wp-admin/admin-ajax.php" \
    "id:1000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"

# Stop rule 942100 inspecting one parameter everywhere
SecAction "id:1000002,phase:1,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:content"
</pre>
</details>
HELP

print_page_end();
&ui_print_footer("", $text{'index_return'});
