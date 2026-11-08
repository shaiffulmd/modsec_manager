#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
&ui_print_header(undef, "Config files", "");
print_nav('config_editor.cgi', 'Edit the main ModSecurity files. Each save is backed up and tested with '.
                               '<code>apachectl configtest</code>; a failing change is rolled back.');

my %targets = editable_config_targets();
my $key = $in{'target'} || 'modsecurity_conf';
my ($label, $file) = editable_config_file($key);
my $data = read_text_file($file);

print "<div class='msm-segctl' role='tablist'>";
foreach my $k ('modsecurity_conf', 'apache_security_conf', 'custom_exclusions') {
    next if (!$targets{$k});
    print "<a href='config_editor.cgi?target=$k'", ($k eq $key ? " class='msm-on' aria-current='page'" : ""), ">",
          &html_escape($targets{$k}->[0]), "</a>";
}
print "</div>\n";
print_readonly_notice();

my $lines = ($data =~ tr/\n//);
print "<div class='msm-panel'><div class='msm-panel-head'><div><div class='msm-panel-title'>", &html_escape($label),
      "</div><div class='msm-panel-sub'><span class='msm-path'>", &html_escape($file), "</span> &middot; ",
      (-e $file ? "$lines lines" : "does not exist yet"), "</div></div></div>\n";
print "<form method='post' action='save_config.cgi'>", &ui_hidden("target", $key);
print text_editor('content', $data, 28);
print "<div class='msm-actions'>", msm_submit("Save and test", 'primary'), "</div>\n" if (can_edit());
print "</form></div>\n";

print_page_end();
&ui_print_footer("", $text{'index_return'});
