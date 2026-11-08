#!/usr/bin/perl
require './modsec-lib.pl';

&ReadParse();
my $file = $in{'file'};
validate_managed_rule_file($file, 1);
&ui_print_header(undef, can_edit() ? "Edit rule file" : "View rule file", "");
print_nav('rules.cgi');

my $data = read_text_file($file);
my $lines = ($data =~ tr/\n//);

print "<p><a href='rules.cgi'>&larr; All rule files</a></p>\n";
if (package_owned_path($file)) {
    print callout('warn', "This file belongs to a package. Changes are lost when the package is upgraded; "
                          . "prefer an <a href='exclusion_builder.cgi'>exclusion</a>.");
}
print_readonly_notice();
print "<div class='msm-panel'><div class='msm-panel-head'><div><div class='msm-panel-title'>",
      &html_escape(File::Basename::basename($file)), "</div><div class='msm-panel-sub'><span class='msm-path'>",
      &html_escape($file), "</span> &middot; $lines lines</div></div></div>\n";
print "<form method='post' action='save_rule.cgi'>", &ui_hidden("file", $file);
print text_editor('content', $data, 30);
print "<div class='msm-actions'>", msm_submit("Save and test", 'primary'), "</div>\n" if (can_edit());
print "</form></div>\n";

print_page_end();
&ui_print_footer("rules.cgi", "rules", "", $text{'index_return'});
