#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Rules", "");
print_nav('rules.cgi', 'Rule and config files ModSecurity loads. Disabling renames a file to <code>.disabled</code>; '.
                       'every change is checked with an Apache config test and undone if it fails.');

my %p = paths();
my $q = defined($in{'q'}) ? $in{'q'} : '';
$q =~ s/^\s+|\s+$//g;
my @all = list_rule_files();
my @files = $q eq '' ? @all : grep { index(lc($_), lc($q)) >= 0 } @all;
my $disabled = grep { !rule_file_enabled($_) } @all;

print "<div class='msm-cards'>",
      "<div class='msm-card'><div class='msm-card-label'>Rule files</div><div class='msm-card-value'>", scalar(@all),
      "</div><div class='msm-card-sub'>In ", scalar(existing_rule_dirs()), " managed directories</div></div>",
      "<div class='msm-card'><div class='msm-card-label'>Disabled</div><div class='msm-card-value'>",
      status_dot($disabled ? 'warn' : 'ok'), $disabled, "</div><div class='msm-card-sub'>Renamed to .disabled</div></div>",
      "</div>\n";
print_readonly_notice();

print "<form method='get' action='rules.cgi' class='msm-filters'>",
      "<input name='q' value='", &html_escape($q), "' placeholder='Filter by name, e.g. 942 or SQL' size='32'>",
      &ui_submit("Filter"), ($q ne '' ? " <a href='rules.cgi'>Clear</a>" : ""), "</form>\n";

# Group by directory.
my (%by, @dirs);
foreach my $f (@files) {
    my ($name, $dir) = File::Basename::fileparse($f);
    $dir =~ s#/$##;
    push(@dirs, $dir) if (!$by{$dir});
    push(@{$by{$dir}}, [$f, $name]);
}

if (!@files) {
    print callout('info', $q ne '' ? "No rule files match <b>" . &html_escape($q) . "</b>."
                                   : "No rule files found in the configured directories.");
}
foreach my $dir (@dirs) {
    print "<div class='msm-h'><span class='msm-path' style='text-transform:none;letter-spacing:0'>",
          &html_escape($dir), "</span>", (package_owned_path("$dir/") ? " &middot; package files" : ""), "</div>\n";
    print "<div class='msm-events'>\n";
    foreach my $r (@{$by{$dir}}) {
        my ($file, $name) = @$r;
        my $enabled = rule_file_enabled($file);
        my $main = same_file($file, $p{modsecurity_conf});
        print "<div class='msm-ins' style='padding:10px 16px'><div class='msm-ins-main'>",
              status_dot($enabled ? 'ok' : 'na'), "<b class='msm-path' style='font-size:13px'>", &html_escape($name), "</b>",
              ($main ? " <span class='msm-badge'>main config</span>" : ""),
              (package_owned_path($file) ? " <span class='msm-badge'>package</span>" : ""),
              (!$enabled ? " <span class='msm-badge'>disabled</span>" : ""),
              "</div><div class='msm-ins-side'>",
              "<a class='msm-btn msm-btn-sm' href='edit_rule.cgi?file=", &url_escape($file), "'>",
              (can_edit() ? "Edit" : "View"), "</a>";
        if (can_edit() && !$main) {
            print "<form method='post' action='toggle_rule.cgi' style='margin:0'>", &ui_hidden("file", $file),
                  &ui_hidden("enable", $enabled ? 0 : 1),
                  "<button type='submit' class='msm-btn msm-btn-sm", ($enabled ? " msm-btn-danger" : ""), "'>",
                  ($enabled ? "Disable" : "Enable"), "</button></form>";
        }
        print "</div></div>\n";
    }
    print "</div>\n";
}

print_page_end();
&ui_print_footer("", $text{'index_return'});
