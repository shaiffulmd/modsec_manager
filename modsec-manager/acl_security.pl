# acl_security.pl
# Per-user access control for the ModSecurity Manager module.

# Load relative to this file: Perl 5.26+ no longer searches '.' for do/require.
use File::Basename ();
do(File::Basename::dirname(__FILE__) . '/modsec-lib.pl');

# Show the ACL editing form in Webmin's user/group editor.
sub acl_security_form {
    my ($acl) = @_;
    my $edit = exists($acl->{'edit'}) ? $acl->{'edit'} : 1;
    print &ui_table_row($text{'acl_edit'} || "Can change ModSecurity settings?",
        &ui_yesno_radio("edit", $edit));
}

# Save the chosen ACL value.
sub acl_security_save {
    my ($acl, $in) = @_;
    $acl->{'edit'} = $in->{'edit'} ? 1 : 0;
}

1;
