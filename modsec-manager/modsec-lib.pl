BEGIN { push(@INC, ".."); }
use Fcntl qw(:DEFAULT O_NOFOLLOW);
use File::Basename ();
use Cwd ();
use POSIX ();
use WebminCore;

&init_config();

# Module access control. Defaults to allowing edits so existing single-admin
# installs keep working; acl_security.pl lets admins grant read-only access.
# Cron jobs (alert.pl) run without a Webmin user and set $no_acl_check.
our %access = $main::no_acl_check ? (edit => 1) : &get_module_acl();
$access{'edit'} = 1 unless exists $access{'edit'};

# Webmin's error() prints its message as HTML. Messages here can contain file
# paths or form input, so always escape them.
sub fail {
    &error(&html_escape(join('', @_)));
}

sub require_edit {
    fail("You do not have permission to change ModSecurity settings.")
        unless $access{'edit'};
}

# Changes must come from a submitted form, never a plain link (GET).
sub require_post {
    fail("This action must be submitted from its form.")
        if (uc($ENV{'REQUEST_METHOD'} || '') ne 'POST');
}

sub can_edit {
    return $access{'edit'} ? 1 : 0;
}

sub cfg {
    my ($key, $default) = @_;
    return defined($config{$key}) && $config{$key} ne '' ? $config{$key} : $default;
}

sub paths {
    return (
        modsecurity_conf       => cfg('modsecurity_conf', '/etc/modsecurity/modsecurity.conf'),
        modsecurity_recommended=> cfg('modsecurity_recommended', '/etc/modsecurity/modsecurity.conf-recommended'),
        apache_security_conf   => cfg('apache_security_conf', '/etc/apache2/mods-available/security2.conf'),
        apache_enabled_conf    => cfg('apache_enabled_conf', '/etc/apache2/mods-enabled/security2.conf'),
        custom_exclusions      => cfg('custom_exclusions', '/etc/modsecurity/modsec-custom-exclusions.conf'),
        audit_log              => cfg('audit_log', '/var/log/apache2/modsec_audit.log'),
        error_log              => cfg('error_log', '/var/log/apache2/error.log'),
        apachectl              => cfg('apachectl', '/usr/sbin/apachectl'),
        systemctl              => cfg('systemctl', '/usr/bin/systemctl'),
        a2enmod                => cfg('a2enmod', '/usr/sbin/a2enmod'),
        a2dismod               => cfg('a2dismod', '/usr/sbin/a2dismod'),
        a2enconf               => cfg('a2enconf', '/usr/sbin/a2enconf'),
        a2disconf              => cfg('a2disconf', '/usr/sbin/a2disconf'),
        ufw                    => cfg('ufw', '/usr/sbin/ufw'),
        apt_get                => cfg('apt_get', '/usr/bin/apt-get'),
        dpkg_query             => cfg('dpkg_query', '/usr/bin/dpkg-query'),
        rule_dirs              => cfg('rule_dirs', '/etc/modsecurity,/etc/modsecurity/crs,/usr/share/modsecurity-crs,/usr/share/modsecurity-crs/rules'),
        tail_lines             => cfg('tail_lines', '5000'),
        apache_sites_dir       => cfg('apache_sites_dir', '/etc/apache2/sites-enabled'),
        crs_setup              => cfg('crs_setup', '/etc/modsecurity/crs/crs-setup.conf'),
        cron_file              => cfg('cron_file', '/etc/cron.d/webmin-modsec-manager'),
    );
}

# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

sub read_text_file {
    my ($file) = @_;
    return '' if (!$file || !-e $file);
    open(my $fh, '<', $file) || fail("Cannot read $file: $!");
    local $/ = undef;
    my $data = <$fh>;
    close($fh);
    return defined($data) ? $data : '';
}

# Browsers submit textareas with CRLF line endings. Apache line continuations
# ("\" at end of line) and some ModSecurity parsing break on a stray \r, so
# store plain LF text with a trailing newline.
sub normalize_text {
    my ($data) = @_;
    $data = '' unless defined $data;
    $data =~ s/\r\n?/\n/g;
    $data .= "\n" if ($data ne '' && substr($data, -1) ne "\n");
    return $data;
}

# Atomic write via an exclusive, no-follow temp file then rename. O_EXCL stops a
# pre-planted temp file from being reused, and O_NOFOLLOW stops a symlinked temp
# from redirecting the write outside the target directory.
#
# If $file is a symlink the write goes to the link target, so the link is kept.
# An existing file keeps its permissions and ownership; $mode/$uid/$gid only
# apply to newly-created files.
sub write_text_file {
    my ($file, $data, $mode, $uid, $gid) = @_;
    if (-l $file) {
        my $real = Cwd::abs_path($file);
        $file = $real if $real;
    }
    if (my @st = stat($file)) {
        $mode = $st[2] & 07777;
        ($uid, $gid) = @st[4, 5];
    }
    $mode = 0644 unless defined $mode;
    my $tmp = "$file.webmin-modsec.tmp.$$";
    unlink($tmp);
    sysopen(my $fh, $tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600)
        || fail("Failed to create temp file $tmp: $!");
    print $fh $data;
    close($fh) || do { unlink($tmp); fail("Failed to write $tmp: $!"); };
    chown($uid, $gid, $tmp) if (defined($uid) && defined($gid));
    chmod($mode, $tmp);
    rename($tmp, $file) || do { unlink($tmp); fail("Failed to replace $file: $!"); };
}

# Backups get the same mode and owner as the original so a 0640 config is not
# exposed as a world-readable .bak file.
sub backup_file {
    my ($file) = @_;
    return undef if (!-e $file);
    my @st = stat($file);
    my ($sec,$min,$hour,$mday,$mon,$year) = localtime(time());
    my $stamp = sprintf("%04d%02d%02d-%02d%02d%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
    my $backup = "$file.webmin-modsec.$stamp.bak";
    write_text_file($backup, read_text_file($file), $st[2] & 07777, $st[4], $st[5]);
    prune_backups($file, 10);
    return $backup;
}

# Keep only the newest $keep backups for a given file so /etc does not grow
# without bound.
sub prune_backups {
    my ($file, $keep) = @_;
    $keep = 10 unless defined $keep;
    my ($name, $dir) = File::Basename::fileparse($file);
    $dir = '.' if $dir eq '';
    opendir(my $dh, $dir) || return;
    my @backups = sort grep { /^\Q$name\E\.webmin-modsec\.\d{8}-\d{6}\.bak$/ } readdir($dh);
    closedir($dh);
    while (@backups > $keep) {
        my $old = shift @backups;
        unlink("$dir/$old");
    }
}

sub restore_backup {
    my ($file, $backup) = @_;
    return 0 if (!$backup || !-e $backup);
    write_text_file($file, read_text_file($backup), 0644);
    return 1;
}

sub remove_created_file {
    my ($file) = @_;
    unlink($file) if ($file && -e $file);
}

# Read the last $n lines of a file without loading the whole file.
sub tail_file {
    my ($file, $n) = @_;
    open(my $fh, '<', $file) || return (undef, "Cannot read $file: $!");
    binmode($fh);
    my $pos = -s $fh;
    my $buf = '';
    my $chunk = 65536;
    while ($pos > 0) {
        my $len = $pos < $chunk ? $pos : $chunk;
        $pos -= $len;
        seek($fh, $pos, 0);
        my $data = '';
        read($fh, $data, $len);
        $buf = $data . $buf;
        last if (($buf =~ tr/\n//) > $n);
        last if (length($buf) > 64 * 1024 * 1024);
    }
    close($fh);
    my @lines = split(/\r?\n/, $buf);
    shift(@lines) if ($pos > 0 && @lines);   # first line is probably partial
    splice(@lines, 0, @lines - $n) if (@lines > $n);
    return (\@lines, undef);
}

# ---------------------------------------------------------------------------
# Command helpers
# ---------------------------------------------------------------------------

sub shell_quote {
    my ($s) = @_;
    $s =~ s/'/'"'"'/g;
    return "'$s'";
}

sub url_escape {
    my ($s) = @_;
    $s = '' unless defined $s;
    $s =~ s/([^A-Za-z0-9_.~-])/sprintf("%%%02X", ord($1))/eg;
    return $s;
}

# Run a command without a shell, returning (exit code, combined stdout+stderr).
# Optional first argument may be a hash ref of extra environment variables.
sub run_command_list {
    my @cmd = @_;
    my $env = ref($cmd[0]) eq 'HASH' ? { %{shift(@cmd)} } : {};
    # Secrets (e.g. a bot token) go to the child on stdin via a private temp
    # file, never on the command line where other users can see them in ps.
    my $stdin = delete $env->{_stdin};
    my $infile;
    if (defined $stdin) {
        require File::Temp;
        my $tfh;
        ($tfh, $infile) = File::Temp::tempfile('modsec-XXXXXXXX', TMPDIR => 1, UNLINK => 0);
        chmod(0600, $infile);
        print $tfh $stdin;
        close($tfh);
    }
    my $pid = open(my $fh, '-|');
    if (!defined $pid) {
        unlink($infile) if ($infile);
        return (127, "Cannot fork: $!");
    }
    if (!$pid) {
        $ENV{$_} = $env->{$_} foreach (keys %$env);
        open(STDIN, '<', $infile || '/dev/null');
        open(STDERR, '>&', \*STDOUT);
        { exec { $cmd[0] } @cmd; }
        print "Cannot run $cmd[0]: $!\n";
        POSIX::_exit(127);
    }
    local $/ = undef;
    my $out = <$fh>;
    close($fh);
    unlink($infile) if ($infile);
    my $code = $? == -1 ? 127 : ($? & 127) ? 128 + ($? & 127) : $? >> 8;
    return ($code, defined($out) ? $out : '');
}

sub package_installed {
    my ($pkg) = @_;
    my %p = paths();
    return 0 if (!-x $p{dpkg_query});
    my ($code, $out) = run_command_list($p{dpkg_query}, '-W', '-f=${Status}', $pkg);
    return $code == 0 && $out =~ /install ok installed/;
}

sub package_version {
    my ($pkg) = @_;
    my %p = paths();
    return '' if (!-x $p{dpkg_query});
    my ($code, $out) = run_command_list($p{dpkg_query}, '-W', '-f=${Status}|${Version}', $pkg);
    return '' if ($code != 0 || $out !~ /install ok installed\|(\S+)/);
    return $1;
}

# ---------------------------------------------------------------------------
# SecRuleEngine
# ---------------------------------------------------------------------------

sub canonical_mode {
    my ($m) = @_;
    return 'On' if lc($m) eq 'on';
    return 'Off' if lc($m) eq 'off';
    return 'DetectionOnly' if lc($m) eq 'detectiononly';
    return undef;
}

# Only matches an active (non-commented) SecRuleEngine directive at the start of
# a line. [ \t]* (not \s*) avoids spanning blank lines.
sub current_engine_mode {
    my %p = paths();
    my $data = read_text_file($p{modsecurity_conf});
    if ($data =~ /^[ \t]*SecRuleEngine[ \t]+(On|Off|DetectionOnly)\b/im) {
        return canonical_mode($1);
    }
    return 'Unknown';
}

sub set_engine_mode {
    my ($mode) = @_;
    $mode = canonical_mode(defined($mode) ? $mode : '') || fail("Invalid SecRuleEngine mode");
    my %p = paths();
    -e $p{modsecurity_conf} || fail("$p{modsecurity_conf} does not exist");
    my $data = read_text_file($p{modsecurity_conf});
    my $backup = backup_file($p{modsecurity_conf});
    # Replace every active directive (preserving indentation); ignore commented
    # example lines. Append if no active directive exists.
    my $count = ($data =~ s/^([ \t]*)SecRuleEngine[ \t]+(?:On|Off|DetectionOnly)\b[^\n]*/${1}SecRuleEngine $mode/mig);
    if (!$count) {
        $data .= "\n" if ($data ne '' && substr($data, -1) ne "\n");
        $data .= "SecRuleEngine $mode\n";
    }
    write_text_file($p{modsecurity_conf}, $data, 0644);
    return $backup;
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

# Everything the status page shows, gathered once.
sub status_overview {
    my %p = paths();
    my %s = (paths => \%p);
    $s{mod_version}   = package_version('libapache2-mod-security2');
    $s{crs_version}   = package_version('modsecurity-crs');
    $s{conf_exists}   = -e $p{modsecurity_conf} ? 1 : 0;
    $s{rec_exists}    = -e $p{modsecurity_recommended} ? 1 : 0;
    $s{apache_exists} = -e $p{apache_security_conf} ? 1 : 0;
    $s{module_on}     = -e $p{apache_enabled_conf} ? 1 : 0;
    $s{engine}        = current_engine_mode();
    $s{excl_exists}   = -e $p{custom_exclusions} ? 1 : 0;
    $s{excl_include}  = custom_exclusions_included();
    $s{audit_log}     = audit_log_path();
    $s{audit_exists}  = -e $s{audit_log} ? 1 : 0;
    $s{audit_size}    = $s{audit_exists} ? (-s $s{audit_log} || 0) : 0;
    $s{rule_dirs}     = [ existing_rule_dirs() ];
    my @files = list_rule_files();
    $s{rule_files}    = scalar(@files);
    $s{rule_disabled} = scalar(grep { !rule_file_enabled($_) } @files);
    return %s;
}

sub human_size {
    my ($n) = @_;
    my @u = ('B', 'KB', 'MB', 'GB');
    my $i = 0;
    while ($n >= 1024 && $i < $#u) { $n /= 1024; $i++; }
    return $i ? sprintf("%.1f %s", $n, $u[$i]) : "$n B";
}

# Returns the Include/IncludeOptional line that loads $target, either literally
# or via a shell glob (e.g. IncludeOptional /etc/modsecurity/*.conf), or '' if
# none does. Used so we don't add a duplicate include of an already-loaded file.
sub line_includes_file {
    my ($content, $target) = @_;
    foreach my $line (split(/\n/, $content)) {
        next unless $line =~ /^[ \t]*(Include(?:Optional)?[ \t]+(\S+))/i;
        my ($directive, $inc) = ($1, $2);
        $inc =~ s/^["']//;
        $inc =~ s/["']$//;
        return $directive if $inc eq $target;
        if ($inc =~ /[*?\[]/) {
            my $re = quotemeta($inc);
            $re =~ s/\\\*/[^\/]*/g;   # * does not cross directory separators
            $re =~ s/\\\?/[^\/]/g;
            return $directive if $target =~ /^$re$/;
        }
    }
    return '';
}

sub custom_exclusions_included {
    my %p = paths();
    my $modsec = read_text_file($p{modsecurity_conf});
    my $apache = read_text_file($p{apache_security_conf});
    return (line_includes_file($modsec, $p{custom_exclusions}) ||
            line_includes_file($apache, $p{custom_exclusions}));
}

sub ensure_custom_exclusions {
    my %p = paths();
    if (!-e $p{custom_exclusions}) {
        write_text_file($p{custom_exclusions}, "# Custom ModSecurity exclusions managed by Webmin\n\n", 0644);
    }
}

# Returns ($message, $backup_path). $backup_path is the modsecurity.conf backup
# made before adding the include (undef if nothing was changed), so the caller
# can roll back on a failed config test.
sub ensure_custom_include {
    my %p = paths();
    ensure_custom_exclusions();
    return ('Already included', undef) if custom_exclusions_included();
    -e $p{modsecurity_conf} || fail("$p{modsecurity_conf} does not exist");
    my $data = read_text_file($p{modsecurity_conf});
    my $backup = backup_file($p{modsecurity_conf});
    $data .= "\n" if ($data ne '' && substr($data, -1) ne "\n");
    $data .= "\n# Custom ModSecurity exclusions managed by Webmin\nIncludeOptional $p{custom_exclusions}\n";
    write_text_file($p{modsecurity_conf}, $data, 0644);
    return ("Added IncludeOptional $p{custom_exclusions}", $backup);
}

# Next free rule id for custom exclusions, in the 1000000+ local range.
sub next_custom_rule_id {
    my %p = paths();
    my $data = read_text_file($p{custom_exclusions});
    my $max = 999999;
    while ($data =~ /\bid[ \t]*:[ \t]*'?(\d+)/g) {
        $max = $1 if ($1 > $max && $1 < 1100000);
    }
    return $max + 1;
}

# ---------------------------------------------------------------------------
# Apache / packages
# ---------------------------------------------------------------------------

sub apache_configtest {
    my %p = paths();
    return run_command_list($p{apachectl}, 'configtest');
}

sub apache_reload {
    my %p = paths();
    my ($code, $out) = apache_configtest();
    return ($code, "Config test failed; Apache was not reloaded.\n\n$out") if ($code != 0);
    my ($rcode, $rout) = run_command_list($p{systemctl}, 'reload', 'apache2');
    return ($rcode, "Config test passed.\n\n$rout");
}

sub create_config_from_recommended {
    my %p = paths();
    -e $p{modsecurity_conf} && return ("Config already exists: $p{modsecurity_conf}", 0);
    -r $p{modsecurity_recommended} || fail("Recommended config not readable: $p{modsecurity_recommended}");
    my $data = read_text_file($p{modsecurity_recommended});
    write_text_file($p{modsecurity_conf}, $data, 0644);
    return ("Created $p{modsecurity_conf} from recommended template", 1);
}

sub enable_apache_security2 {
    my %p = paths();
    return (0, "Apache ModSecurity module already enabled.\n") if (-e $p{apache_enabled_conf});
    return run_command_list($p{a2enmod}, 'security2');
}

sub disable_apache_security2 {
    my %p = paths();
    return (0, "Apache ModSecurity module already disabled.\n") if (!-e $p{apache_enabled_conf});
    return run_command_list($p{a2dismod}, 'security2');
}

# apt must never prompt: there is no terminal behind a CGI request. Keep the
# admin's version of any changed conffile (e.g. /etc/modsecurity/crs/crs-setup.conf).
sub apt_env {
    return { DEBIAN_FRONTEND => 'noninteractive', APT_LISTCHANGES_FRONTEND => 'none' };
}

sub apt_update {
    my %p = paths();
    return run_command_list(apt_env(), $p{apt_get}, '-q', 'update');
}

sub apt_upgrade_modsecurity {
    my %p = paths();
    my @pkgs = grep { package_installed($_) } ('libapache2-mod-security2', 'modsecurity-crs');
    return (1, "Neither libapache2-mod-security2 nor modsecurity-crs is installed.\n") if (!@pkgs);
    return run_command_list(apt_env(), $p{apt_get}, '-q', '-y',
        '-o', 'Dpkg::Options::=--force-confdef',
        '-o', 'Dpkg::Options::=--force-confold',
        'install', '--only-upgrade', @pkgs);
}

# ---------------------------------------------------------------------------
# Rule files
# ---------------------------------------------------------------------------

sub configured_rule_dirs {
    my %p = paths();
    my @dirs = split(/\s*,\s*/, $p{rule_dirs});
    return grep { $_ ne '' } @dirs;
}

sub existing_rule_dirs {
    my %seen;
    return grep { -d $_ && !$seen{Cwd::abs_path($_) || $_}++ } configured_rule_dirs();
}

sub path_under_dir {
    my ($path, $dir) = @_;
    my $ap = Cwd::abs_path($path);
    my $ad = Cwd::abs_path($dir);
    return 0 if (!$ap || !$ad);
    return $ap eq $ad || index($ap, "$ad/") == 0;
}

sub same_file {
    my ($a, $b) = @_;
    return 0 if (!$a || !$b || !-e $a || !-e $b);
    my $ra = Cwd::abs_path($a);
    my $rb = Cwd::abs_path($b);
    return $ra && $rb && $ra eq $rb;
}

sub validate_managed_rule_file {
    my ($file, $must_exist) = @_;
    fail("No file selected") if (!$file);
    fail("Relative paths are not allowed") if ($file !~ m#^/#);
    fail("Parent directory paths are not allowed") if ($file =~ m#(?:^|/)\.\.(?:/|$)#);
    fail("Unsupported file type") unless ($file =~ /\.(?:conf|load|rules)(?:\.disabled)?$/);
    fail("File does not exist: $file") if ($must_exist && !-e $file);
    my $check = -e $file ? $file : File::Basename::dirname($file);
    foreach my $dir (existing_rule_dirs()) {
        return 1 if path_under_dir($check, $dir);
    }
    fail("File is outside managed rule directories: $file");
}

sub list_rule_files {
    my @files;
    foreach my $dir (existing_rule_dirs()) {
        opendir(my $dh, $dir) || next;
        foreach my $name (sort readdir($dh)) {
            next if $name =~ /^\./;
            my $file = "$dir/$name";
            next if !-f $file;
            next if $file !~ /\.(?:conf|load|rules)(?:\.disabled)?$/;
            push(@files, $file);
        }
        closedir($dh);
    }
    return @files;
}

sub rule_file_enabled {
    my ($file) = @_;
    return $file !~ /\.disabled$/;
}

# Files under /usr are owned by a package and get replaced on upgrade.
sub package_owned_path {
    my ($file) = @_;
    return $file =~ m#^/usr/#;
}

sub toggle_rule_file {
    my ($file, $enable) = @_;
    validate_managed_rule_file($file, 1);
    my %p = paths();
    fail("The main ModSecurity config cannot be disabled here. Use Enforcement mode instead.")
        if same_file($file, $p{modsecurity_conf});
    my $target;
    if ($enable) {
        fail("Rule file is already enabled") if ($file !~ /\.disabled$/);
        $target = $file;
        $target =~ s/\.disabled$//;
    } else {
        fail("Rule file is already disabled") if ($file =~ /\.disabled$/);
        $target = "$file.disabled";
    }
    fail("Target already exists: $target") if (-e $target);
    rename($file, $target) || fail("Failed to rename $file: $!");
    return $target;
}

sub revert_rule_toggle {
    my ($from, $to) = @_;
    rename($to, $from) if ($from && $to && -e $to && !-e $from);
}

sub editable_config_targets {
    my %p = paths();
    return (
        modsecurity_conf => ['ModSecurity main config', $p{modsecurity_conf}],
        apache_security_conf => ['Apache security2 config', $p{apache_security_conf}],
        custom_exclusions => ['Custom exclusions', $p{custom_exclusions}],
    );
}

sub editable_config_file {
    my ($key) = @_;
    my %targets = editable_config_targets();
    fail("Unknown config target") if (!defined($key) || !$targets{$key});
    return @{$targets{$key}};
}

# Save $data to $file, run apachectl configtest and roll back on failure. A
# file that did not exist before is removed again on failure.
sub save_file_with_configtest {
    my ($file, $data) = @_;
    my $existed = -e $file;
    my $backup = backup_file($file);
    write_text_file($file, normalize_text($data), 0644);
    my ($code, $out) = apache_configtest();
    my $reverted = 0;
    if ($code != 0) {
        if ($existed) {
            $reverted = restore_backup($file, $backup);
        } else {
            remove_created_file($file);
            $reverted = 1;
        }
    }
    return ($code, $out, $backup, $reverted);
}

# ---------------------------------------------------------------------------
# Logs
# ---------------------------------------------------------------------------

# Configured audit log, or the SecAuditLog path from modsecurity.conf when the
# configured file does not exist.
sub audit_log_path {
    my %p = paths();
    return $p{audit_log} if (-e $p{audit_log});
    my $data = read_text_file($p{modsecurity_conf});
    if ($data =~ /^[ \t]*SecAuditLog[ \t]+"?([^"\s|][^"\s]*)"?/im) {
        my $f = $1;
        return $f if ($f =~ m#^/# && -e $f);
    }
    return $p{audit_log};
}

sub tail_line_limit {
    my %p = paths();
    my $lines = $p{tail_lines};
    $lines =~ s/\D//g;
    $lines ||= 5000;
    $lines = 20000 if ($lines > 20000);
    return $lines;
}

# Pull the bracketed metadata ModSecurity appends to each message.
sub parse_modsec_message {
    my ($text) = @_;
    my %m = ( text => $text );
    foreach my $k ('id', 'msg', 'severity', 'data', 'hostname', 'uri', 'unique_id', 'file') {
        $m{$k} = $1 if ($text =~ /\[\Q$k\E "((?:[^"\\]|\\.)*)"\]/);
    }
    if (!$m{msg}) {
        my $short = $text;
        $short =~ s/\s*\[[a-z_]+ "(?:[^"\\]|\\.)*"\].*$//s;
        $short =~ s/^(?:Message:\s*)?//;
        $m{msg} = $short;
    }
    return \%m;
}

sub new_transaction {
    my ($id) = @_;
    return { id => $id, messages => [] };
}

# Parse ModSecurity 2 Serial audit log lines into transactions.
sub parse_serial_audit {
    my ($lines) = @_;
    my @tx;
    my ($cur, $section, $first_in_section);
    my %by_id;
    foreach my $line (@$lines) {
        if ($line =~ /^--([0-9A-Za-z]+)-([A-Z])--$/) {
            my ($id, $sec) = ($1, $2);
            if (!$by_id{$id}) {
                $by_id{$id} = new_transaction($id);
                push(@tx, $by_id{$id});
            }
            $cur = $by_id{$id};
            $section = $sec;
            $first_in_section = 1;
            next;
        }
        next if (!$cur || !defined($section));
        if ($section eq 'A' && $line =~ /^\[([^\]]+)\]\s+(\S+)\s+(\S+)\s+(\d+)/) {
            ($cur->{time}, $cur->{unique_id}, $cur->{client}) = ($1, $2, $3);
        } elsif ($section eq 'B') {
            if ($first_in_section && $line =~ /^[A-Z]+ \S/) {
                $cur->{request} = $line;
            } elsif ($line =~ /^Host:\s*(.+?)\s*$/i) {
                $cur->{host} = $1;
            }
        } elsif ($section eq 'F' && $first_in_section && $line =~ /^HTTP\/\S+\s+(\d{3})/) {
            $cur->{status} = $1;
        } elsif ($section eq 'H') {
            if ($line =~ /^Message:\s*(.*)$/) {
                push(@{$cur->{messages}}, parse_modsec_message($1));
            } elsif ($line =~ /^Action:\s*(.*)$/) {
                $cur->{action} = $1;
            }
        }
        $first_in_section = 0 if ($line ne '');
    }
    return @tx;
}

# Parse one JSON audit record (ModSecurity 2.9 or libmodsecurity 3 layout).
sub parse_json_audit {
    my ($line) = @_;
    my $j = eval { require JSON::PP; JSON::PP->new->allow_nonref->decode($line) };
    return undef if (!$j || ref($j) ne 'HASH');
    my $t = $j->{transaction} || {};
    my $tx = new_transaction($t->{transaction_id} || $t->{unique_id} || '');
    $tx->{time} = $t->{time} || $t->{time_stamp};
    $tx->{client} = $t->{remote_address} || $t->{client_ip};
    my $req = $j->{request} || $t->{request} || {};
    my $hdr = $req->{headers} || {};
    my ($host_key) = grep { lc($_) eq 'host' } keys %$hdr;
    $tx->{host} = $hdr->{$host_key} if $host_key;
    $tx->{request} = $req->{request_line} ||
        join(' ', grep { defined } ($req->{method}, $req->{uri}));
    my $resp = $j->{response} || $t->{response} || {};
    $tx->{status} = $resp->{status} || $resp->{http_code};
    my $ad = $j->{audit_data} || {};
    foreach my $m (@{$ad->{messages} || []}) {
        push(@{$tx->{messages}}, parse_modsec_message($m)) if (!ref($m));
    }
    foreach my $m (@{$t->{messages} || []}) {
        next if (ref($m) ne 'HASH');
        my $d = $m->{details} || {};
        push(@{$tx->{messages}}, {
            text => $m->{message}, msg => $m->{message}, id => $d->{ruleId},
            severity => $d->{severity}, data => $d->{data},
        });
    }
    if (ref($ad->{action}) eq 'HASH') {
        $tx->{action} = $ad->{action}{intercepted} ? "Intercepted (phase $ad->{action}{phase})" : '';
    }
    return $tx;
}

# Parse "ModSecurity:" lines from the Apache error log; one event per line.
sub parse_error_log {
    my ($lines) = @_;
    my @tx;
    foreach my $line (@$lines) {
        next if ($line !~ /ModSecurity:\s*(.*)$/);
        my $m = parse_modsec_message($1);
        my $tx = new_transaction($m->{unique_id} || '');
        $tx->{time} = $1 if ($line =~ /^\[([^\]]+)\]/);
        $tx->{client} = $1 if ($line =~ /\[client ([^\]]+)\]/);
        $tx->{client} =~ s/:\d+$// if ($tx->{client} && $tx->{client} =~ /^[\d.]+:\d+$/);
        $tx->{host} = $m->{hostname};
        $tx->{request} = $m->{uri};
        $tx->{action} = $m->{text} =~ /^Access denied/ ? 'Intercepted' : '';
        $tx->{messages} = [ $m ];
        push(@tx, $tx);
    }
    return @tx;
}

# Returns (\@raw_lines, \@transactions, $file, $error). Transactions are newest
# first. $source is 'audit' or 'error'.
sub read_recent_log {
    my ($source, $history) = @_;
    my %p = paths();
    my $file = $source eq 'error' ? $p{error_log} : audit_log_path();
    return ([], [], $file, "Log file not found: $file") if (!-e $file);
    my ($lines, $err) = tail_file($file, tail_line_limit());
    return ([], [], $file, $err) if (!$lines);
    if ($history) {
        my @old = read_rotated_lines($file, $history);
        $lines = [ @old, @$lines ];
        splice(@$lines, 0, @$lines - max_history_lines()) if (@$lines > max_history_lines());
    }
    my @tx;
    if ($source eq 'error') {
        @tx = parse_error_log($lines);
    } elsif (grep { /^\s*\{/ } @$lines[0 .. ($#$lines < 20 ? $#$lines : 20)]) {
        @tx = grep { $_ } map { /^\s*\{/ ? parse_json_audit($_) : () } @$lines;
    } else {
        @tx = parse_serial_audit($lines);
        # Fall back to error-log style lines if the file is not Serial format.
        @tx = parse_error_log($lines) if (!@tx);
    }
    @tx = grep { @{$_->{messages}} || $_->{action} } @tx;
    return ($lines, [ reverse @tx ], $file, undef);
}

# Aggregate rule hits: list of { id, msg, severity, count, last_uri }.
sub rule_hit_summary {
    my ($txs) = @_;
    my %hits;
    foreach my $tx (@$txs) {
        foreach my $m (@{$tx->{messages}}) {
            next if (!$m->{id});
            my $h = $hits{$m->{id}} ||= { id => $m->{id}, count => 0 };
            $h->{count}++;
            $h->{msg} ||= $m->{msg};
            $h->{severity} ||= $m->{severity};
            if (!$h->{uri} && $tx->{request}) {
                my $uri = $tx->{request};
                $uri =~ s/^[A-Z]+\s+//;
                $uri =~ s/\s+HTTP\/\S+$//;
                $uri =~ s/\?.*$//;
                $h->{uri} = $uri;
            }
        }
    }
    return sort { $b->{count} <=> $a->{count} || $a->{id} cmp $b->{id} } values %hits;
}

# ---------------------------------------------------------------------------
# Log analytics (for the charts on logs.cgi)
# ---------------------------------------------------------------------------

sub tx_blocked {
    my ($tx) = @_;
    return 1 if (($tx->{action} || '') =~ /Intercepted/i);
    return 1 if (($tx->{status} || '') =~ /^(?:403|406|501)$/ && @{$tx->{messages}});
    return 1 if (grep { ($_->{text} || '') =~ /^(?:Message:\s*)?Access denied/ } @{$tx->{messages}});
    return 0;
}

sub tx_path {
    my ($tx) = @_;
    my $uri = $tx->{request} || '';
    $uri =~ s/^[A-Z]+\s+//;
    $uri =~ s/\s+HTTP\/\S+$//;
    $uri =~ s/\?.*$//;
    return $uri eq '-' ? '' : $uri;
}

# Epoch seconds from the time formats ModSecurity and Apache write:
#   08/Nov/2026:10:00:00.123456 +0800      (audit log, JSON v2)
#   Sun Nov 08 10:02:00.123456 2026        (error log, libmodsecurity 3)
# Times are taken as written (local server time); the zone is ignored.
sub log_time_epoch {
    my ($t) = @_;
    return undef if (!$t);
    my %mon = (jan=>0, feb=>1, mar=>2, apr=>3, may=>4, jun=>5, jul=>6, aug=>7, sep=>8, oct=>9, nov=>10, dec=>11);
    my ($d, $m, $y, $H, $M, $S);
    if ($t =~ m#^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d\d):(\d\d):(\d\d)#) {
        ($d, $m, $y, $H, $M, $S) = ($1, $2, $3, $4, $5, $6);
    } elsif ($t =~ /^[A-Za-z]{3}\s+([A-Za-z]{3})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)(?:\.\d+)?\s+(\d{4})/) {
        ($m, $d, $H, $M, $S, $y) = ($1, $2, $3, $4, $5, $6);
    } else {
        return undef;
    }
    my $mi = $mon{lc($m)};
    return undef if (!defined $mi);
    require Time::Local;
    return eval { Time::Local::timegm($S, $M, $H, $d, $mi, $y) };
}

# Keep transactions matching every non-empty filter in %f
# (rule, ip, host, path, blocked).
sub filter_transactions {
    my ($txs, %f) = @_;
    return grep {
        my $tx = $_;
        (!$f{rule} || grep { ($_->{id} || '') eq $f{rule} } @{$tx->{messages}}) &&
        (!$f{ip}   || ($tx->{client} || '') eq $f{ip}) &&
        (!$f{host} || ($tx->{host} || '') eq $f{host}) &&
        (!$f{hosts} || $f{hosts}{norm_host($tx->{host})}) &&
        (!$f{path} || tx_path($tx) eq $f{path}) &&
        (!$f{blocked} || tx_blocked($tx))
    } @$txs;
}

# Distinct rule IDs per transaction, so a rule counts once per request.
sub tx_rule_ids {
    my ($tx) = @_;
    my %s = map { $_->{id} => 1 } grep { $_->{id} } @{$tx->{messages}};
    return keys %s;
}

# Top values of a per-transaction key: list of [value, count, blocked].
sub top_values {
    my ($txs, $getter, $limit) = @_;
    my (%n, %b);
    foreach my $tx (@$txs) {
        foreach my $v ($getter->($tx)) {
            next if (!defined($v) || $v eq '');
            $n{$v}++;
            $b{$v}++ if tx_blocked($tx);
        }
    }
    my @rows = map { [$_, $n{$_}, $b{$_} || 0] }
               sort { $n{$b} <=> $n{$a} || $a cmp $b } keys %n;
    splice(@rows, $limit) if ($limit && @rows > $limit);
    return @rows;
}

# Events per time bucket. Hourly when the window spans up to 48 hours, daily
# otherwise. Empty buckets are filled so the time axis is continuous.
# Returns (\@buckets, $unit) where each bucket is
# { start => epoch, total => n, blocked => n }.
sub event_timeline {
    my ($txs, $range_txs) = @_;
    my @t = grep { defined $_->[0] } map { [log_time_epoch($_->{time}), $_] } @$txs;
    # The axis spans $range_txs (e.g. the unfiltered events) so a filtered
    # view keeps the same time axis as the full one.
    my @r = grep { defined } map { log_time_epoch($_->{time}) } @{$range_txs || $txs};
    return ([], 'hour') if (!@r);
    my ($min, $max) = (sort { $a <=> $b } @r)[0, -1];
    my $unit = ($max - $min) <= 48 * 3600 ? 'hour' : 'day';
    my $size = $unit eq 'hour' ? 3600 : 86400;
    my $first = $min - ($min % $size);
    my $last = $max - ($max % $size);
    $first = $last - 59 * $size if (($last - $first) / $size > 59);   # at most 60 bars
    my %b;
    foreach my $p (@t) {
        my $k = $p->[0] - ($p->[0] % $size);
        next if ($k < $first);
        $b{$k}{total}++;
        $b{$k}{blocked}++ if tx_blocked($p->[1]);
    }
    my @buckets;
    for (my $k = $first; $k <= $last; $k += $size) {
        push(@buckets, { start => $k, total => $b{$k}{total} || 0, blocked => $b{$k}{blocked} || 0 });
    }
    return (\@buckets, $unit);
}

# "08 Nov 12:49:05" from any supported log timestamp (raw text if unknown).
sub short_log_time {
    my ($t) = @_;
    my $e = log_time_epoch($t);
    return defined($t) ? $t : '' if (!defined $e);
    my @g = gmtime($e);
    my @mn = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    return sprintf("%02d %s %02d:%02d:%02d", $g[3], $mn[$g[4]], $g[2], $g[1], $g[0]);
}

sub bucket_label {
    my ($epoch, $unit, $long) = @_;
    my @g = gmtime($epoch);
    my @mn = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my $day = sprintf("%d %s", $g[3], $mn[$g[4]]);
    return $unit eq 'day' ? $day : $long ? sprintf("%s %02d:00", $day, $g[2]) : sprintf("%02d:00", $g[2]);
}

# ---------------------------------------------------------------------------
# Rotated logs
# ---------------------------------------------------------------------------

sub max_history_lines { return 200000; }

# Lines from up to $n rotated copies of $file (oldest first): file.1, file.2.gz...
# Only the newest max_history_lines() lines are kept in memory.
sub read_rotated_lines {
    my ($file, $n) = @_;
    $n = 7 if ($n > 7);
    my @lines;
    my $max = max_history_lines();
    for (my $i = $n; $i >= 1; $i--) {
        my ($f) = grep { -r $_ } ("$file.$i", "$file.$i.gz");
        next if (!$f);
        my $fh;
        if ($f =~ /\.gz$/) {
            require IO::Uncompress::Gunzip;
            $fh = IO::Uncompress::Gunzip->new($f) || next;
        } else {
            open($fh, '<', $f) || next;
        }
        while (my $l = <$fh>) {
            $l =~ s/\r?\n$//;
            push(@lines, $l);
            shift(@lines) if (@lines > $max);
        }
        close($fh);
    }
    return @lines;
}

# Rotated copies that exist for the configured log, for the UI.
sub rotated_log_count {
    my ($file) = @_;
    my $n = 0;
    for (my $i = 1; $i <= 7; $i++) {
        last if (!-e "$file.$i" && !-e "$file.$i.gz");
        $n = $i;
    }
    return $n;
}

# ---------------------------------------------------------------------------
# Rules, targets and sites
# ---------------------------------------------------------------------------

# CRS anomaly-score evaluation rules: they fire because other rules matched,
# so they are never the thing to exclude.
sub is_score_rule {
    my ($id) = @_;
    return defined($id) && $id =~ /^(?:949110|949111|959100|959101|980099|980100|980130|980140|980170)$/;
}

my $TARGET_COLLECTIONS = 'ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|'.
                         'REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|'.
                         'XML|FILES|FILES_NAMES|REQUEST_BODY';

# The part of the request a rule matched, e.g. "ARGS:comment", taken from
#   [data "Matched Data: ... found within ARGS:comment: ..."]   or
#   "Pattern match ... at ARGS:comment. [file ...]"
sub message_target {
    my ($m) = @_;
    my $d = $m->{data} || '';
    my $t = $m->{text} || '';
    return $1 if ($d =~ /\bwithin ((?:$TARGET_COLLECTIONS)(?::[^:\s]+)?):/o);
    return $1 if ($t =~ /\bat ((?:$TARGET_COLLECTIONS)(?::\S+?)?)\.(?:\s|$)/o);
    return undef;
}

sub norm_host {
    my ($h) = @_;
    $h = lc(defined($h) ? $h : '');
    $h =~ s/^\[([0-9a-f:]+)\](?::\d+)?$/$1/;   # [ipv6]:port
    $h =~ s/:\d+$// if ($h !~ /:.*:/);
    $h =~ s/\.$//;
    return $h;
}

# Apache virtual hosts from the enabled sites:
# list of { name, aliases => [], ports => [], docroot, files => [] }.
sub apache_vhosts {
    my %p = paths();
    my $dir = $p{apache_sites_dir};
    my (%by, @order);
    opendir(my $dh, $dir) || return ();
    foreach my $f (sort grep { !/^\./ } readdir($dh)) {
        my $path = "$dir/$f";
        next if (!-f $path);
        my $data = read_text_file($path);
        while ($data =~ /<VirtualHost\s+([^>]*)>(.*?)<\/VirtualHost>/sgi) {
            my ($addr, $body) = ($1, $2);
            $body =~ s/^[ \t]*#.*$//mg;
            my ($name) = $body =~ /^[ \t]*ServerName[ \t]+(\S+)/mi;
            next if (!$name);
            $name = norm_host($name);
            my @aliases;
            while ($body =~ /^[ \t]*ServerAlias[ \t]+(.+)$/mgi) {
                push(@aliases, map { norm_host($_) } split(/\s+/, $1));
            }
            my ($docroot) = $body =~ /^[ \t]*DocumentRoot[ \t]+"?([^"\s]+)/mi;
            my @ports = $addr =~ /:(\d+)/g;
            my $v = $by{$name};
            if (!$v) {
                $v = $by{$name} = { name => $name, aliases => [], ports => [], files => [] };
                push(@order, $name);
            }
            my %a = map { $_ => 1 } @{$v->{aliases}};
            push(@{$v->{aliases}}, grep { $_ ne $name && !$a{$_}++ } @aliases);
            my %pt = map { $_ => 1 } @{$v->{ports}};
            push(@{$v->{ports}}, grep { !$pt{$_}++ } @ports);
            push(@{$v->{files}}, $path) if (!grep { $_ eq $path } @{$v->{files}});
            $v->{docroot} ||= $docroot;
        }
    }
    closedir($dh);
    return map { $by{$_} } @order;
}

# Name of the vhost that serves $host ('' if none), honouring *.wildcard aliases.
sub site_for_host {
    my ($host, $vhosts) = @_;
    $host = norm_host($host);
    return '' if ($host eq '');
    foreach my $v (@$vhosts) {
        return $v->{name} if ($v->{name} eq $host);
        foreach my $a (@{$v->{aliases}}) {
            return $v->{name} if ($a eq $host);
            if ($a =~ /[*?]/) {
                my $re = quotemeta($a);
                $re =~ s/\\\*/.*/g;
                $re =~ s/\\\?/./g;
                return $v->{name} if ($host =~ /^$re$/);
            }
        }
    }
    return '';
}

# ---------------------------------------------------------------------------
# Exclusion builder
# ---------------------------------------------------------------------------

# Validate builder input. Returns (\%clean, $error).
sub clean_exclusion_input {
    my (%o) = @_;
    my %c;
    $c{rule} = defined($o{rule}) ? $o{rule} : '';
    $c{rule} =~ s/^\s+|\s+$//g;
    return (undef, "Enter a numeric rule ID") if ($c{rule} !~ /^\d{1,9}$/);
    return (undef, "Rule $c{rule} is an anomaly-score total. Exclude the rules that raised the score instead.")
        if (is_score_rule($c{rule}));
    $c{host} = norm_host($o{host});
    return (undef, "Invalid host name") if ($c{host} ne '' && $c{host} !~ /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/);
    $c{path} = defined($o{path}) ? $o{path} : '';
    $c{path} =~ s/^\s+|\s+$//g;
    return (undef, "The path must start with /") if ($c{path} ne '' && $c{path} !~ m#^/#);
    return (undef, "The path may not contain spaces, quotes or backslashes")
        if ($c{path} =~ /[\s"'\\]/);
    $c{match} = ($o{match} || '') eq 'exact' ? 'exact' : 'begins';
    $c{target} = defined($o{target}) ? $o{target} : '';
    $c{target} =~ s/^\s+|\s+$//g;
    $c{target} = '' if (($o{scope} || '') eq 'rule');
    return (undef, "Invalid request part. Use e.g. ARGS:comment, ARGS_NAMES or REQUEST_COOKIES:session")
        if ($c{target} ne '' && $c{target} !~ /^(?:$TARGET_COLLECTIONS)(?::[A-Za-z0-9_.\-\[\]\/]+)?$/o);
    return (\%c, undef);
}

sub describe_exclusion {
    my ($c) = @_;
    my $what = $c->{target} ne '' ? "stop rule $c->{rule} inspecting $c->{target}" : "turn off rule $c->{rule}";
    my $where = $c->{host} ne '' ? "on $c->{host}" : "on every site";
    $where .= $c->{path} ne '' ? ($c->{match} eq 'exact' ? " for $c->{path}" : " under $c->{path}")
                               : ", every path";
    return "$what $where";
}

# ModSecurity config text for an exclusion. Runtime ctl: actions in phase 1,
# so it works even though this file is loaded before the CRS rules.
sub build_exclusion {
    my ($c, $id, $note) = @_;
    my $ctl = $c->{target} ne '' ? "ctl:ruleRemoveTargetById=$c->{rule};$c->{target}"
                                 : "ctl:ruleRemoveById=$c->{rule}";
    my @cond;
    push(@cond, ['SERVER_NAME', "\@streq $c->{host}", 't:none,t:lowercase,']) if ($c->{host} ne '');
    push(@cond, ['REQUEST_FILENAME', ($c->{match} eq 'exact' ? '@streq ' : '@beginsWith ') . $c->{path}, 't:none,'])
        if ($c->{path} ne '');
    my $txt = "# " . ucfirst(describe_exclusion($c)) . ($note ? " ($note)" : "") . "\n";
    if (!@cond) {
        $txt .= "SecAction \"id:$id,phase:1,pass,nolog,$ctl\"\n";
    } elsif (@cond == 1) {
        $txt .= "SecRule $cond[0][0] \"$cond[0][1]\" \\\n    \"id:$id,phase:1,pass,nolog,$cond[0][2]$ctl\"\n";
    } else {
        $txt .= "SecRule $cond[0][0] \"$cond[0][1]\" \\\n    \"id:$id,phase:1,pass,nolog,$cond[0][2]chain\"\n".
                "    SecRule $cond[1][0] \"$cond[1][1]\" \\\n        \"$cond[1][2]$ctl\"\n";
    }
    return $txt;
}

# Per-rule details from the log for the builder: hosts, paths and request
# parts the rule matched, each as [value, count] sorted by count.
sub rule_log_details {
    my ($txs, $rule) = @_;
    my (%h, %p, %t, $msg, $n);
    foreach my $tx (@$txs) {
        my @m = grep { ($_->{id} || '') eq $rule } @{$tx->{messages}};
        next if (!@m);
        $n++;
        $msg ||= $m[0]{msg};
        $h{norm_host($tx->{host})}++ if ($tx->{host});
        my $path = tx_path($tx);
        $p{$path}++ if ($path ne '');
        my %seen;
        foreach my $m (@m) {
            my $tg = message_target($m);
            $t{$tg}++ if ($tg && !$seen{$tg}++);
        }
    }
    my $sorted = sub { my %x = @_; [ map { [$_, $x{$_}] } sort { $x{$b} <=> $x{$a} || $a cmp $b } keys %x ] };
    return { count => $n || 0, msg => $msg, hosts => $sorted->(%h), paths => $sorted->(%p), targets => $sorted->(%t) };
}

# Append an exclusion and roll back if Apache rejects it.
# Returns ($code, $out, $backup, $reverted, $include_msg).
sub append_exclusion {
    my ($text, $ensure_include) = @_;
    my %p = paths();
    ensure_custom_exclusions();
    my $data = normalize_text(read_text_file($p{custom_exclusions}));
    $data .= "\n" if ($data ne '' && $data !~ /\n\n$/);
    my ($inc_msg, $inc_backup) = ('', undef);
    if ($ensure_include) {
        ($inc_msg, $inc_backup) = ensure_custom_include();
    }
    my ($code, $out, $backup, $reverted) = save_file_with_configtest($p{custom_exclusions}, $data . $text);
    restore_backup($p{modsecurity_conf}, $inc_backup) if ($code != 0 && $inc_backup);
    return ($code, $out, $backup, $reverted, $inc_msg);
}

# ---------------------------------------------------------------------------
# Insights: likely false positives vs likely attackers
# ---------------------------------------------------------------------------

# Heuristics, not verdicts:
#  - an attacker is a client that trips many different rules, sends many
#    flagged requests, or is flagged as a scanner (CRS 913xxx);
#  - a false-positive candidate is one rule on one site and path that several
#    ordinary (non-attacker) clients trip.
sub log_insights {
    my ($txs) = @_;
    my %ip;
    foreach my $tx (@$txs) {
        my $c = $tx->{client} || next;
        my $s = $ip{$c} ||= { ip => $c, events => 0, blocked => 0, rules => {}, hosts => {} };
        $s->{events}++;
        $s->{blocked}++ if tx_blocked($tx);
        $s->{hosts}{norm_host($tx->{host})}++ if ($tx->{host});
        foreach my $id (tx_rule_ids($tx)) {
            next if (is_score_rule($id));
            $s->{rules}{$id}++;
            $s->{scanner} = 1 if ($id =~ /^913\d{3}$/);
        }
    }
    my @attackers;
    foreach my $s (values %ip) {
        my $nr = scalar(keys %{$s->{rules}});
        my @why;
        push(@why, "flagged as a scanner") if ($s->{scanner});
        push(@why, "$nr different rules") if ($nr >= 4);
        push(@why, "$s->{events} flagged requests") if ($s->{events} >= 20);
        next if (!@why);
        $s->{reason} = join(', ', @why);
        $s->{nrules} = $nr;
        ($s->{top_rule}) = sort { $s->{rules}{$b} <=> $s->{rules}{$a} } keys %{$s->{rules}};
        push(@attackers, $s);
    }
    @attackers = sort { $b->{events} <=> $a->{events} } @attackers;
    my %bad = map { $_->{ip} => 1 } @attackers;

    my %g;
    foreach my $tx (@$txs) {
        my $c = $tx->{client} || next;
        next if ($bad{$c});
        my $host = norm_host($tx->{host});
        my $path = tx_path($tx);
        foreach my $m (@{$tx->{messages}}) {
            my $id = $m->{id} || next;
            next if (is_score_rule($id) || $id =~ /^913\d{3}$/);
            my $k = join("\0", $id, $host, $path);
            my $e = $g{$k} ||= { rule => $id, host => $host, path => $path, msg => $m->{msg},
                                 hits => 0, clients => {}, targets => {} };
            $e->{hits}++;
            $e->{clients}{$c}++;
            my $tg = message_target($m);
            $e->{targets}{$tg}++ if ($tg);
        }
    }
    my @fp;
    foreach my $e (values %g) {
        $e->{nclients} = scalar(keys %{$e->{clients}});
        next if ($e->{nclients} < 3);
        ($e->{target}) = sort { $e->{targets}{$b} <=> $e->{targets}{$a} } keys %{$e->{targets}};
        push(@fp, $e);
    }
    @fp = sort { $b->{nclients} <=> $a->{nclients} || $b->{hits} <=> $a->{hits} } @fp;
    splice(@fp, 10) if (@fp > 10);
    splice(@attackers, 10) if (@attackers > 10);
    return (\@fp, \@attackers);
}

# ---------------------------------------------------------------------------
# CRS settings (paranoia level, anomaly thresholds) in crs-setup.conf
# ---------------------------------------------------------------------------

# Split config text into directives, joining "\" continuation lines.
# Returns list of { first, last, text, active } (0-based line numbers).
sub config_directives {
    my ($data) = @_;
    my @lines = split(/\n/, $data, -1);
    my @d;
    my $i = 0;
    while ($i < @lines) {
        my $first = $i;
        my $text = $lines[$i];
        while ($lines[$i] =~ /\\\s*$/ && $i + 1 < @lines) {
            $i++;
            $text .= "\n" . $lines[$i];
        }
        push(@d, { first => $first, last => $i, text => $text, active => ($text !~ /^\s*#/ && $text =~ /\S/ ? 1 : 0) });
        $i++;
    }
    return @d;
}

sub crs_settings {
    my %p = paths();
    my $data = read_text_file($p{crs_setup});
    my %s = (file => $p{crs_setup}, exists => (-e $p{crs_setup} ? 1 : 0),
             crs4 => ($data =~ /blocking_paranoia_level/ ? 1 : 0),
             paranoia => 1, inbound => 5, outbound => 4, set => {});
    foreach my $d (grep { $_->{active} } config_directives($data)) {
        my $t = $d->{text};
        if ($t =~ /tx\.(?:blocking_)?paranoia_level=(\d)/) { $s{paranoia} = $1; $s{set}{paranoia} = 1; }
        if ($t =~ /tx\.inbound_anomaly_score_threshold=(\d+)/) { $s{inbound} = $1; $s{set}{inbound} = 1; }
        if ($t =~ /tx\.outbound_anomaly_score_threshold=(\d+)/) { $s{outbound} = $1; $s{set}{outbound} = 1; }
    }
    return %s;
}

# Rewrite paranoia/threshold settings: drop active SecActions 900000/900110
# and append one managed block. Returns save_file_with_configtest() results.
sub save_crs_settings {
    my ($pl, $in, $out) = @_;
    fail("Paranoia level must be 1 to 4") if ($pl !~ /^[1-4]$/);
    fail("Thresholds must be whole numbers from 1 to 1000")
        if ($in !~ /^\d{1,4}$/ || $out !~ /^\d{1,4}$/ || $in < 1 || $out < 1 || $in > 1000 || $out > 1000);
    my %s = crs_settings();
    fail("CRS setup file not found: $s{file}") if (!$s{exists});
    my $data = read_text_file($s{file});
    my @lines = split(/\n/, $data, -1);
    my %drop;
    foreach my $d (config_directives($data)) {
        next if (!$d->{active});
        next if ($d->{text} !~ /^\s*SecAction\b/ || $d->{text} !~ /\bid:'?(900000|900110)\b/);
        $drop{$_} = 1 for ($d->{first} .. $d->{last});
    }
    my @keep = map { $lines[$_] } grep { !$drop{$_} } 0 .. $#lines;
    my $new = join("\n", @keep);
    $new =~ s/\n*# --- Managed by Webmin ModSecurity Manager ---\n*$/\n/s;
    $new =~ s/\n*$/\n/;
    my $plvar = $s{crs4} ? 'tx.blocking_paranoia_level' : 'tx.paranoia_level';
    $new .= "\n# --- Managed by Webmin ModSecurity Manager ---\n".
            "SecAction \"id:900000,phase:1,pass,nolog,t:none,setvar:$plvar=$pl\"\n".
            "SecAction \"id:900110,phase:1,pass,nolog,t:none,".
            "setvar:tx.inbound_anomaly_score_threshold=$in,setvar:tx.outbound_anomaly_score_threshold=$out\"\n";
    return save_file_with_configtest($s{file}, $new);
}

# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

sub alert_settings {
    return (
        enabled   => cfg('alert_enabled', 0) ? 1 : 0,
        interval  => cfg('alert_interval', 15),
        threshold => cfg('alert_threshold', 50),
        cooldown  => cfg('alert_cooldown', 60),
        email     => cfg('alert_email', ''),
        tg_token  => cfg('alert_telegram_token', ''),
        tg_chat   => cfg('alert_telegram_chat', ''),
    );
}

# Log timestamps carry local wall-clock time; compare like with like.
sub local_now_epoch {
    require Time::Local;
    my @l = localtime(time());
    return Time::Local::timegm(@l[0 .. 5]);
}

# Blocked events in the last $minutes. Returns (\@blocked_txs, $since_epoch).
sub recent_blocked {
    my ($minutes) = @_;
    my ($raw, $txs) = read_recent_log('audit');
    my $since = local_now_epoch() - $minutes * 60;
    my @b = grep { my $t = log_time_epoch($_->{time}); defined($t) && $t >= $since && tx_blocked($_) } @$txs;
    return (\@b, $since);
}

# Link to this module in Webmin for alert messages: the alert_webmin_url
# setting, else Webmin's own idea of its URL, else https://host:port/.
sub webmin_module_url {
    my $u = cfg('alert_webmin_url', '');
    $u =~ s/\s+//g;
    if ($u !~ m#^https?://[^\s"'<>]+$#) {
        $u = '';
        if (defined(&get_webmin_browser_url)) {
            $u = eval { &get_webmin_browser_url($module_name) } || '';
        }
        if (!$u) {
            my %mini;
            eval { &get_miniserv_config(\%mini) } if (defined(&get_miniserv_config));
            my $port = $mini{'port'} || 10000;
            my $proto = (!%mini || $mini{'ssl'}) ? 'https' : 'http';
            $u = "$proto://" . &get_system_hostname() . ":$port/" . ($module_name || 'modsec-manager') . "/";
        }
    }
    $u .= '/' if ($u !~ m#/$#);
    return $u;
}

# "1 request", "5 requests".
sub plural {
    my ($n, $word) = @_;
    return "$n $word" . ($n == 1 ? "" : "s");
}

# Everything an alert says, gathered once for the text and HTML versions.
sub alert_report {
    my ($txs, $minutes, $test) = @_;
    my %a = alert_settings();
    my %m = module_meta();
    my @vh = apache_vhosts();
    my %msg;
    foreach my $tx (@$txs) {
        foreach my $mm (@{$tx->{messages}}) {
            $msg{$mm->{id}} ||= $mm->{msg} if ($mm->{id});
        }
    }
    my %clients = map { ($_->{client} || '') => 1 } @$txs;
    delete $clients{''};
    my @l = localtime(time());
    my @mn = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my @rules = grep { !is_score_rule($_->[0]) } top_values($txs, \&tx_rule_ids);
    my %r = (
        host      => &get_system_hostname(),
        n         => scalar(@$txs),
        minutes   => $minutes,
        threshold => $a{threshold},
        cooldown  => $a{cooldown},
        test      => $test ? 1 : 0,
        version   => $m{version},
        time      => sprintf("%d %s %d, %02d:%02d", $l[3], $mn[$l[4]], $l[5] + 1900, $l[2], $l[1]),
        url       => webmin_module_url(),
        clients   => scalar(keys %clients),
        rules_n   => scalar(@rules),
        sites     => [ top_values($txs, sub { site_for_host($_[0]{host}, \@vh) || norm_host($_[0]{host}) || '(no host)' }, 5) ],
        ips       => [ top_values($txs, sub { $_[0]{client} }, 5) ],
        rules     => [ map { [ $_->[0], $_->[1], $msg{$_->[0]} || '' ] } (@rules > 5 ? @rules[0 .. 4] : @rules) ],
        paths     => [ top_values($txs, \&tx_path, 5) ],
    );
    $r{sites_n} = scalar(top_values($txs, sub { site_for_host($_[0]{host}, \@vh) || norm_host($_[0]{host}) }));
    return \%r;
}

sub alert_text {
    my ($r) = @_;
    my $line = ('-' x 56) . "\n";
    my $t = ($r->{test} ? "TEST ALERT - no action needed\n\n" : "") .
            "ModSecurity blocked " . plural($r->{n}, "request") . " in the last $r->{minutes} minutes\n" .
            "Server: $r->{host}\nTime:   $r->{time}\nAlert threshold: $r->{threshold} per $r->{minutes} minutes\n\n" .
            sprintf("%-14s %d\n%-14s %d\n%-14s %d\n", 'Sites hit:', $r->{sites_n}, 'Clients:', $r->{clients},
                    'Rules:', $r->{rules_n});
    my $sec = sub {
        my ($title, $rows, $fmt) = @_;
        return '' if (!@$rows);
        return "\n$title\n$line" . join('', map { $fmt->($_) } @$rows);
    };
    $t .= $sec->('TOP SITES', $r->{sites}, sub { sprintf("%6d  %s\n", $_[0][1], $_[0][0]) });
    $t .= $sec->('TOP CLIENTS', $r->{ips}, sub { sprintf("%6d  %s\n", $_[0][1], $_[0][0]) });
    $t .= $sec->('TOP RULES', $r->{rules}, sub { sprintf("%6d  %s  %s\n", $_[0][1], $_[0][0], substr($_[0][2], 0, 60)) });
    $t .= $sec->('TOP PATHS', $r->{paths}, sub { sprintf("%6d  %s\n", $_[0][1], $_[0][0]) });
    $t .= "\nOpen the logs: $r->{url}logs.cgi?blocked=1\n" .
          "\n--\nModSecurity Manager $r->{version} on $r->{host}\n" .
          "At most one alert is sent every $r->{cooldown} minutes. Change this under Alerts in the module.\n";
    return $t;
}

# Email-safe HTML: table layout, inline styles, no images or scripts.
# Every value from the log is escaped.
sub alert_html {
    my ($r) = @_;
    my $e = sub { &html_escape(defined($_[0]) ? $_[0] : '') };
    my $font = "font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif";
    my $mono = "font-family:SFMono-Regular,Menlo,Consolas,Liberation Mono,monospace";
    my $stat = sub {
        my ($label, $value) = @_;
        return "<td width='25%' align='center' style='padding:14px 6px;border-right:1px solid #eef0f4'>" .
               "<div style='$font;font-size:22px;font-weight:700;color:#111827;line-height:1.2'>" . $e->($value) . "</div>" .
               "<div style='$font;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#6b7280;margin-top:4px'>" .
               $e->($label) . "</div></td>";
    };
    my $section = sub {
        my ($title, $rows, $mono_label, $sub) = @_;
        return '' if (!@$rows);
        my $max = $rows->[0][1] || 1;
        my $h = "<tr><td style='padding:22px 32px 0'>" .
                "<div style='$font;font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#6b7280;margin:0 0 8px'>" .
                $e->($title) . "</div><table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='border-collapse:collapse'>";
        foreach my $row (@$rows) {
            my $w = int(100 * $row->[1] / $max + 0.5);
            $w = 3 if ($w < 3);
            $h .= "<tr><td style='padding:7px 0;border-top:1px solid #eef0f4;$font;font-size:13px;color:#111827'>" .
                  "<div style='" . ($mono_label ? "$mono;font-size:12.5px;" : "") . "word-break:break-all'>" . $e->($row->[0]) .
                  ($sub && $sub->($row) ne '' ? "<span style='$font;font-size:12px;color:#6b7280'> &middot; " . $e->($sub->($row)) . "</span>" : "") .
                  "</div><div style='background:#eef2fb;border-radius:4px;height:6px;margin-top:5px'>" .
                  "<div style='width:$w%;background:#2f6fed;height:6px;border-radius:4px'></div></div></td>" .
                  "<td width='56' align='right' valign='top' style='padding:7px 0 7px 12px;border-top:1px solid #eef0f4;$font;font-size:13px;font-weight:600;color:#111827'>" .
                  $e->($row->[1]) . "</td></tr>";
        }
        return $h . "</table></td></tr>";
    };
    my $pre = $r->{test} ? "Test alert from ModSecurity Manager on $r->{host}"
                         : plural($r->{n}, "blocked request") . " in $r->{minutes} minutes on $r->{host}";
    my $html = "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>" .
        "<meta name='color-scheme' content='light only'><title>" . $e->("ModSecurity alert") . "</title></head>" .
        "<body style='margin:0;padding:0;background:#f3f5f9'>" .
        "<div style='display:none;max-height:0;overflow:hidden;opacity:0'>" . $e->($pre) . "</div>" .
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0' style='background:#f3f5f9'><tr><td align='center' style='padding:28px 12px'>" .
        "<table role='presentation' width='600' cellpadding='0' cellspacing='0' style='width:100%;max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;border:1px solid #e5e8ef'>";

    # Header
    $html .= "<tr><td style='background:#1d4ed8;background-image:linear-gradient(135deg,#3b82f6,#1d4ed8);padding:22px 32px'>" .
        "<table role='presentation' width='100%' cellpadding='0' cellspacing='0'><tr>" .
        "<td width='44' valign='middle'><div style='width:40px;height:40px;border-radius:11px;background:rgba(255,255,255,.18);" .
        "text-align:center;line-height:40px;font-size:20px;color:#ffffff'>&#128737;</div></td>" .
        "<td valign='middle' style='padding-left:12px'><div style='$font;font-size:16px;font-weight:700;color:#ffffff'>ModSecurity Manager</div>" .
        "<div style='$font;font-size:12.5px;color:#dbe6ff'>" . $e->($r->{host}) . "</div></td>" .
        "<td align='right' valign='middle'><span style='display:inline-block;$font;font-size:11.5px;font-weight:700;letter-spacing:.04em;" .
        "color:#ffffff;background:" . ($r->{test} ? "rgba(255,255,255,.22)" : "#d64545") . ";border-radius:999px;padding:5px 11px'>" .
        ($r->{test} ? "TEST" : "ALERT") . "</span></td></tr></table></td></tr>";

    # Headline
    $html .= "<tr><td style='padding:28px 32px 8px'>" .
        ($r->{test} ? "<div style='$font;font-size:13px;color:#1d4ed8;background:#eef2ff;border-radius:8px;padding:9px 12px;margin:0 0 16px'>" .
                      "This is a test message. Your alert settings work; no action is needed.</div>" : "") .
        "<div style='$font;font-size:13px;font-weight:600;color:#d64545;letter-spacing:.02em'>Spike in blocked requests</div>" .
        "<div style='$font;font-size:26px;font-weight:700;color:#111827;line-height:1.25;margin-top:4px'>" .
        $e->(plural($r->{n}, "request")) . " blocked in " . $e->($r->{minutes}) . " minutes</div>" .
        "<div style='$font;font-size:14px;color:#4b5563;margin-top:8px;line-height:1.5'>ModSecurity on <b>" . $e->($r->{host}) .
        "</b> blocked more requests than your alert threshold of <b>" . $e->($r->{threshold}) . "</b> per " .
        $e->($r->{minutes}) . " minutes. Reported " . $e->($r->{time}) . ".</div></td></tr>";

    # Stats
    $html .= "<tr><td style='padding:16px 32px 4px'><table role='presentation' width='100%' cellpadding='0' cellspacing='0' " .
        "style='border:1px solid #eef0f4;border-radius:10px;border-collapse:separate'><tr>" .
        $stat->('Blocked', $r->{n}) . $stat->('Sites', $r->{sites_n}) . $stat->('Clients', $r->{clients}) .
        "<td width='25%' align='center' style='padding:14px 6px'><div style='$font;font-size:22px;font-weight:700;color:#111827;line-height:1.2'>" .
        $e->($r->{rules_n}) . "</div><div style='$font;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:#6b7280;margin-top:4px'>Rules</div></td>" .
        "</tr></table></td></tr>";

    # Breakdown
    $html .= $section->('Top sites', $r->{sites}, 0);
    $html .= $section->('Top clients', $r->{ips}, 1);
    $html .= $section->('Top rules', $r->{rules}, 0, sub { $_[0][2] });
    $html .= $section->('Top paths', $r->{paths}, 1);

    # Call to action
    $html .= "<tr><td style='padding:26px 32px 30px'>" .
        "<table role='presentation' cellpadding='0' cellspacing='0'><tr><td style='border-radius:9px;background:#2f6fed'>" .
        "<a href='" . $e->("$r->{url}logs.cgi?blocked=1") . "' style='display:inline-block;padding:12px 20px;$font;font-size:14px;" .
        "font-weight:600;color:#ffffff;text-decoration:none;border-radius:9px'>Review blocked requests &rarr;</a></td></tr></table>" .
        "<div style='$font;font-size:12.5px;color:#6b7280;margin-top:12px;line-height:1.5'>If these are real users, " .
        "use <b>Possible false positives</b> on the Logs page to build a scoped exclusion. " .
        "If they come from a few clients, block them in the firewall.</div></td></tr>";

    # Footer
    $html .= "<tr><td style='background:#f8f9fc;border-top:1px solid #eef0f4;padding:16px 32px'>" .
        "<div style='$font;font-size:12px;color:#6b7280;line-height:1.55'>Sent by ModSecurity Manager " . $e->($r->{version}) .
        " on " . $e->($r->{host}) . ". At most one alert is sent every " . $e->($r->{cooldown}) .
        " minutes.<br>Change these alerts in Webmin &rsaquo; Servers &rsaquo; ModSecurity Manager &rsaquo; Alerts.</div></td></tr>";
    $html .= "</table></td></tr></table></body></html>\n";
    return $html;
}

# Returns ($subject, $text, $html).
sub alert_message {
    my ($txs, $minutes, $test) = @_;
    my $r = alert_report($txs, $minutes, $test);
    my $subject = ($test ? "[TEST] " : "") . "ModSecurity: " . plural($r->{n}, "blocked request") . " in $minutes min on $r->{host}";
    return ($subject, alert_text($r), alert_html($r));
}

# A multipart/alternative message (plain text + HTML), UTF-8.
sub build_mime_message {
    my ($from, $to, $subject, $text, $html) = @_;
    require MIME::Base64;
    require MIME::QuotedPrint;
    foreach my $v (\$from, \$to, \$subject) { $$v =~ s/[\r\n]+/ /g; }
    foreach my $v (\$text, \$html) { utf8::encode($$v) if (utf8::is_utf8($$v)); }
    my @d = qw(Sun Mon Tue Wed Thu Fri Sat);
    my @mn = qw(Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec);
    my @l = localtime(time());
    my $date = sprintf("%s, %02d %s %04d %02d:%02d:%02d %s", $d[$l[6]], $l[3], $mn[$l[4]], $l[5] + 1900,
                       $l[2], $l[1], $l[0], POSIX::strftime("%z", @l));
    my $host = &get_system_hostname();
    my $b = "=_msm_" . time() . "_" . $$ . "_" . int(rand(1e9));
    return "From: $from\nTo: $to\nSubject: $subject\nDate: $date\n" .
           "Message-ID: <msm." . time() . ".$$\@$host>\nMIME-Version: 1.0\n" .
           "Auto-Submitted: auto-generated\nX-Mailer: ModSecurity Manager\n" .
           "Content-Type: multipart/alternative; boundary=\"$b\"\n\n" .
           "This is a multi-part message in MIME format.\n\n" .
           "--$b\nContent-Type: text/plain; charset=UTF-8\nContent-Transfer-Encoding: quoted-printable\n\n" .
           MIME::QuotedPrint::encode_qp($text) . "\n" .
           "--$b\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: base64\n\n" .
           MIME::Base64::encode_base64($html) .
           "--$b--\n";
}

# Send to every configured channel. Returns list of [channel, ok, message].
# E-mail goes out as HTML + text through the local sendmail; without one it
# falls back to Webmin's mail module with the text version.
sub send_alert {
    my ($subject, $text, $html) = @_;
    my %a = alert_settings();
    my @res;
    if ($a{email}) {
        my $addr = cfg('alert_from', 'webmin@' . &get_system_hostname());
        $addr =~ s/[\r\n<>"]+//g;
        my $from = "\"ModSecurity Manager\" <$addr>";
        my $how = '';
        my $ok = eval {
            if (-x '/usr/sbin/sendmail' && $html) {
                open(my $mh, '|-', '/usr/sbin/sendmail', '-t', '-oi', '-f', $addr) || die "cannot run sendmail: $!\n";
                print $mh build_mime_message($from, $a{email}, $subject, $text, $html);
                close($mh) || die "sendmail exited with an error\n";
                $how = 'HTML';
            } elsif (&foreign_check("mailboxes")) {
                &foreign_require("mailboxes", "mailboxes-lib.pl");
                &mailboxes::send_text_mail($addr, $a{email}, undef, $subject, $text);
                $how = 'plain text';
            } else {
                die "no sendmail and no Webmin mail module\n";
            }
            1;
        };
        push(@res, ['email', $ok ? 1 : 0, $ok ? "Sent to $a{email} ($how)" : "Failed: $@"]);
    }
    if ($a{tg_token} && $a{tg_chat}) {
        my $url = "https://api.telegram.org/bot$a{tg_token}/sendMessage";
        my $msg_text = "$subject\n\n$text";
        $msg_text = substr($msg_text, 0, 4000) if (length($msg_text) > 4000);
        my ($ok, $msg);
        require HTTP::Tiny;
        if (HTTP::Tiny->can_ssl()) {
            my $r = HTTP::Tiny->new(timeout => 15)->post_form($url, { chat_id => $a{tg_chat}, text => $msg_text,
                                                                       disable_web_page_preview => 'true' });
            ($ok, $msg) = ($r->{success}, $r->{success} ? "Sent to chat $a{tg_chat}" : "HTTP $r->{status}: $r->{content}");
        } elsif (-x '/usr/bin/curl') {
            (my $q = $url) =~ s/(["\\])/\\$1/g;
            my ($code, $out) = run_command_list({ _stdin => "url = \"$q\"\n" }, '/usr/bin/curl', '-sS', '-m', '15',
                '--fail-with-body', '-K', '-', '--data-urlencode', "chat_id=$a{tg_chat}",
                '--data-urlencode', "disable_web_page_preview=true", '--data-urlencode', "text=$msg_text");
            ($ok, $msg) = ($code == 0, $code == 0 ? "Sent to chat $a{tg_chat}" : "curl failed: $out");
        } else {
            ($ok, $msg) = (0, "No HTTPS client available (install libio-socket-ssl-perl or curl)");
        }
        $msg =~ s/\Q$a{tg_token}\E/<token>/g;
        push(@res, ['telegram', $ok ? 1 : 0, $msg]);
    }
    return @res;
}

# Install or remove the cron entry that runs alert.pl.
sub write_alert_cron {
    my ($enabled, $interval) = @_;
    my %p = paths();
    if (!$enabled) {
        unlink($p{cron_file}) if (-e $p{cron_file});
        return;
    }
    $interval = 15 if ($interval !~ /^\d+$/ || $interval < 1 || $interval > 60);
    my $root = $module_root_directory || Cwd::getcwd();
    my $cfgdir = $config_directory || '/etc/webmin';
    my $var = $var_directory || '/var/webmin';
    write_text_file($p{cron_file},
        "# ModSecurity block alerts, managed by Webmin ModSecurity Manager\n".
        "*/$interval * * * * root cd $root && WEBMIN_CONFIG=$cfgdir WEBMIN_VAR=$var /usr/bin/perl $root/alert.pl >/dev/null 2>&1\n",
        0644);
}

sub alert_state_file {
    return ($module_config_directory || "/etc/webmin/modsec-manager") . "/alert.state";
}

# ---------------------------------------------------------------------------
# Cloudflare readiness
# ---------------------------------------------------------------------------
# Sending attacker IPs to Cloudflare only works if ModSecurity logs each
# visitor's real address. Behind Cloudflare's proxy that needs mod_remoteip to
# read CF-Connecting-IP, and to accept that header from Cloudflare's own
# addresses only. Without it the log holds Cloudflare edge addresses, or
# anyone can fake the header and get an innocent address blocked.

# Cloudflare's published ranges (https://www.cloudflare.com/ips/), used when
# the live list cannot be fetched and no saved copy exists.
my @CF_BUILTIN_RANGES = qw(
    173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18
    108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17
    162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22
    2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32
    2a06:98c0::/29 2c0f:f248::/32
);

# Packed IPv4 (4 bytes) or IPv6 (16 bytes) address, or undef. IPv4-mapped
# IPv6 addresses (::ffff:1.2.3.4) come back as IPv4.
sub ip_pack {
    my ($ip) = @_;
    return undef if (!defined($ip));
    $ip =~ s/^\[(.*)\]$/$1/;
    $ip =~ s/%.*$//;
    require Socket;
    if ($ip =~ /^\d{1,3}(?:\.\d{1,3}){3}$/) {
        return Socket::inet_pton(Socket::AF_INET(), $ip);
    }
    return undef if ($ip !~ /:/ || $ip !~ /^[0-9a-f:.]+$/i);
    my $b = Socket::inet_pton(Socket::AF_INET6(), $ip);
    return substr($b, 12) if (defined($b) && substr($b, 0, 12) eq ("\0" x 10) . "\xff\xff");
    return $b;
}

# "addr", "addr/len" or "addr/255.255.0.0" -> { net, len, text }, or undef.
sub cidr_parse {
    my ($s) = @_;
    return undef if (!defined($s));
    my ($addr, $mask) = split(m#/#, $s, 2);
    my $net = ip_pack($addr);
    return undef if (!defined($net));
    my $max = length($net) * 8;
    my $len = $max;
    if (defined($mask)) {
        if ($mask =~ /^\d{1,3}$/) {
            $len = $mask;
        } elsif (length($net) == 4 && defined(my $m = ip_pack($mask))) {
            my $bits = unpack('B32', $m);
            return undef if ($bits !~ /^(1*)0*$/);
            $len = length($1);
        } else {
            return undef;
        }
    }
    return undef if ($len > $max);
    return { net => $net, len => $len, text => $s };
}

# True if parsed range $outer contains parsed range (or address) $inner.
sub cidr_contains {
    my ($outer, $inner) = @_;
    return 0 if (length($outer->{net}) != length($inner->{net}) || $outer->{len} > $inner->{len});
    my $n = $outer->{len};
    return substr(unpack('B*', $outer->{net}), 0, $n) eq substr(unpack('B*', $inner->{net}), 0, $n);
}

sub ip_in_ranges {
    my ($ip, $ranges) = @_;
    my $c = cidr_parse($ip) || return 0;
    foreach my $r (@$ranges) {
        return 1 if (cidr_contains($r, $c));
    }
    return 0;
}

# Small HTTPS client: HTTP::Tiny when it has SSL support, else curl. Header
# values (such as an API token) and the body reach curl on stdin, never on
# the command line. Returns ($ok, $body, $error, $status).
sub https_request {
    my ($method, $url, $headers, $body) = @_;
    $headers ||= {};
    my %m = module_meta();
    my $agent = "webmin-modsec-manager/$m{version}";
    require HTTP::Tiny;
    if (HTTP::Tiny->can_ssl()) {
        my $r = HTTP::Tiny->new(timeout => 10, agent => $agent)->request($method, $url,
            { headers => $headers, (defined($body) ? (content => $body) : ()) });
        my $err = $r->{success} ? undef : $r->{status} == 599 ? $r->{content} : "HTTP $r->{status} $r->{reason}";
        return ($r->{success} ? 1 : 0, $r->{content}, $err, $r->{status});
    }
    return (0, '', "No HTTPS client available (install libio-socket-ssl-perl or curl)", 0)
        if (!-x '/usr/bin/curl');
    my $q = sub {
        my ($s) = @_;
        $s =~ s/(["\\])/\\$1/g;
        $s =~ s/\r/\\r/g;
        $s =~ s/\n/\\n/g;
        return "\"$s\"";
    };
    my $conf = "url = " . $q->($url) . "\nrequest = " . $q->($method) . "\nuser-agent = " . $q->($agent) . "\n";
    $conf .= "header = " . $q->("$_: $headers->{$_}") . "\n" foreach (sort keys %$headers);
    $conf .= "data-raw = " . $q->($body) . "\n" if (defined($body));
    $conf .= "write-out = " . $q->("\n%{http_code}") . "\n";
    my ($code, $out) = run_command_list({ _stdin => $conf }, '/usr/bin/curl', '-sS', '-m', '10', '-K', '-');
    return (0, '', "curl failed: $out", 0) if ($code != 0);
    my $status = $out =~ s/\n?(\d{3})\s*$// ? $1 : 0;
    my $ok = $status >= 200 && $status < 300 ? 1 : 0;
    return ($ok, $out, $ok ? undef : "HTTP $status", $status);
}

sub cf_ranges_cache_file {
    return ($module_config_directory || "/etc/webmin/modsec-manager") . "/cloudflare-ips.txt";
}

# Cloudflare's address ranges as text CIDRs. With $live, ask the Cloudflare
# API first and save the answer; otherwise (or if that fails) use the saved
# copy, then the built-in list. Returns (\@ranges, $source, $error) where
# $source is 'live', 'saved' or 'built-in'.
sub cf_ip_ranges {
    my ($live) = @_;
    my $err;
    my $cache = cf_ranges_cache_file();
    if ($live) {
        my ($ok, $body, $e) = https_request('GET', 'https://api.cloudflare.com/client/v4/ips');
        my $j = $ok ? eval { require JSON::PP; JSON::PP->new->decode($body) } : undef;
        my $res = ref($j) eq 'HASH' && $j->{success} && ref($j->{result}) eq 'HASH' ? $j->{result} : {};
        my @l = grep { !ref($_) && cidr_parse($_) }
                (@{$res->{ipv4_cidrs} || []}, @{$res->{ipv6_cidrs} || []});
        if (@l >= 5) {
            my $dir = File::Basename::dirname($cache);
            write_text_file($cache, "# Cloudflare IP ranges from api.cloudflare.com, saved by ModSecurity Manager\n" .
                                    join("\n", @l) . "\n", 0644) if (-d $dir && -w $dir);
            return (\@l, 'live', undef);
        }
        $err = $ok ? "Unexpected answer from the Cloudflare API" : ($e || 'Request failed');
    }
    my @saved = grep { cidr_parse($_) } map { /^\s*([0-9a-f:.\/]+)\s*$/i ? $1 : () }
                split(/\n/, read_text_file($cache));
    return (\@saved, 'saved', $err) if (@saved >= 5);
    return ([ @CF_BUILTIN_RANGES ], 'built-in', $err);
}

# Apache's configuration root (/etc/apache2), from the security2.conf path.
sub apache_root {
    my %p = paths();
    my $d = File::Basename::dirname(File::Basename::dirname($p{apache_enabled_conf}));
    return -d "$d/mods-available" ? $d : '/etc/apache2';
}

# The files Apache loads on Debian/Ubuntu: apache2.conf, ports.conf and the
# enabled modules, conf snippets and sites.
sub apache_loaded_files {
    my %p = paths();
    my $root = apache_root();
    my @f = ("$root/apache2.conf", "$root/ports.conf");
    foreach my $d (["$root/mods-enabled", qr/\.(?:load|conf)$/], ["$root/conf-enabled", qr/\.conf$/],
                   [$p{apache_sites_dir}, qr/\.conf$/]) {
        opendir(my $dh, $d->[0]) || next;
        push(@f, map { "$d->[0]/$_" } sort grep { /$d->[1]/ } readdir($dh));
        closedir($dh);
    }
    return grep { -f $_ } @f;
}

# Is an Apache module loaded? Asks apachectl -M, else looks in mods-enabled.
sub apache_module_loaded {
    my ($name) = @_;
    my %p = paths();
    if (-x $p{apachectl}) {
        my ($code, $out) = run_command_list($p{apachectl}, '-M');
        return $out =~ /^\s*\Q$name\E_module\b/m ? 1 : 0 if ($code == 0);
    }
    return -e apache_root() . "/mods-enabled/$name.load" ? 1 : 0;
}

# mod_remoteip directives in the loaded config:
# list of { directive (lower case), args, file, line, vhost (inside <VirtualHost>) }.
sub remoteip_directives {
    my @d;
    foreach my $f (apache_loaded_files()) {
        my ($depth, $n) = (0, 0);
        foreach my $l (split(/\n/, read_text_file($f))) {
            $n++;
            next if ($l =~ /^\s*#/);
            if ($l =~ /^\s*<VirtualHost\b/i) { $depth++; next; }
            if ($l =~ /^\s*<\/VirtualHost\s*>/i) { $depth-- if ($depth); next; }
            next if ($l !~ /^\s*(RemoteIP(?:Header|TrustedProxyList|TrustedProxy|InternalProxyList|InternalProxy))\s+(.*?)\s*$/i);
            push(@d, { directive => lc($1), args => $2, file => $f, line => $n, vhost => $depth ? 1 : 0 });
        }
    }
    return @d;
}

# Name and paths of the conf snippet this module manages.
sub cf_realip_conf_name { return 'remoteip-cloudflare'; }
sub cf_realip_conf_file { return apache_root() . "/conf-available/" . cf_realip_conf_name() . ".conf"; }
sub cf_realip_conf_link { return apache_root() . "/conf-enabled/" . cf_realip_conf_name() . ".conf"; }

sub is_managed_realip_file {
    my ($f) = @_;
    return File::Basename::basename($f) eq cf_realip_conf_name() . ".conf" ? 1 : 0;
}

# $carry: extra directive lines kept from settings moved out of other files.
sub cf_realip_conf_text {
    my ($ranges, $carry) = @_;
    $carry ||= [];
    return "# Real visitor addresses for sites behind Cloudflare.\n" .
           "# Managed by Webmin ModSecurity Manager (Cloudflare page); changes here are overwritten.\n" .
           "<IfModule remoteip_module>\n" .
           "    RemoteIPHeader CF-Connecting-IP\n" .
           join('', map { "    RemoteIPTrustedProxy $_\n" } @$ranges) .
           (@$carry ? "    # Kept from the settings moved here from other files\n" .
                      join('', map { "    $_\n" } @$carry) : "") .
           "</IfModule>\n";
}

# Real-IP settings outside the managed snippet (for example a Cloudflare
# setup pasted into a Virtualmin VirtualHost) can be moved into it: the old
# lines are commented out, and any trusted proxy that is not Cloudflare's
# (such as 127.0.0.1 for a tunnel) is kept. This is only offered when every
# header there is one Cloudflare sends, so a setup for another proxy is
# never taken over. Ranges that trust almost everyone are dropped.
# Returns { ok, reason, edits => [directives], carry => [lines], files => [paths], dropped => [entries] }.
sub cf_migration_plan {
    my ($dirs, $cf) = @_;
    my @foreign = grep { !is_managed_realip_file($_->{file}) } @$dirs;
    my %plan = (ok => 0, reason => '', edits => [], carry => [], files => [], dropped => []);
    my @headers = grep { $_->{directive} eq 'remoteipheader' } @foreign;
    return \%plan if (!@headers);
    foreach my $h (@headers) {
        my $name = (split(/\s+/, $h->{args}))[0] || '';
        next if (lc($name) eq 'cf-connecting-ip' || lc($name) eq 'x-forwarded-for');
        $plan{reason} = "$h->{file} line $h->{line} sets RemoteIPHeader $name, which Cloudflare does not send, " .
                        "so it is probably for another proxy. Change that file by hand.";
        return \%plan;
    }
    my %canon = (remoteiptrustedproxy => 'RemoteIPTrustedProxy', remoteipinternalproxy => 'RemoteIPInternalProxy',
                 remoteiptrustedproxylist => 'RemoteIPTrustedProxyList',
                 remoteipinternalproxylist => 'RemoteIPInternalProxyList');
    my (%seen, %files);
    foreach my $d (@foreign) {
        push(@{$plan{edits}}, $d);
        $files{$d->{file}} = 1;
        next if ($d->{directive} eq 'remoteipheader');
        my $name = $canon{$d->{directive}};
        if ($d->{directive} =~ /list$/) {
            my $l = "$name $d->{args}";
            push(@{$plan{carry}}, $l) if (!$seen{lc($l)}++);
            next;
        }
        foreach my $i (grep { $_ ne '' } split(/\s+/, $d->{args})) {
            my $c = cidr_parse($i);
            next if ($c && grep { cidr_contains($_, $c) } @$cf);
            if ($c && $c->{len} < (length($c->{net}) == 4 ? 8 : 16)) {
                push(@{$plan{dropped}}, $i) if (!$seen{"drop $i"}++);
                next;
            }
            my $l = "$name $i";
            push(@{$plan{carry}}, $l) if (!$seen{lc($l)}++);
        }
    }
    $plan{files} = [ sort keys %files ];
    $plan{ok} = 1;
    return \%plan;
}

# Comment out the given RemoteIP* lines (1-based) of a file, in place. A
# symlinked file (sites-enabled -> sites-available) is changed at its target.
sub comment_out_remoteip_lines {
    my ($file, $lines) = @_;
    my @l = split(/\n/, read_text_file($file), -1);
    foreach my $n (@$lines) {
        next if ($n < 1 || $n > @l || $l[$n - 1] !~ /^\s*RemoteIP/i);
        $l[$n - 1] =~ s/^(\s*)/$1# Moved to remoteip-cloudflare.conf by Webmin ModSecurity Manager: /;
    }
    write_text_file($file, join("\n", @l), 0644);
}

# Addresses a host name resolves to (IPv4 and IPv6, de-duplicated).
sub resolve_host {
    my ($host) = @_;
    require Socket;
    my ($err, @res) = Socket::getaddrinfo($host, undef, { socktype => Socket::SOCK_STREAM() });
    return () if ($err);
    my (%seen, @ips);
    foreach my $r (@res) {
        my $ip;
        if ($r->{family} == Socket::AF_INET()) {
            my (undef, $a) = Socket::unpack_sockaddr_in($r->{addr});
            $ip = Socket::inet_ntop(Socket::AF_INET(), $a);
        } elsif ($r->{family} == Socket::AF_INET6()) {
            my (undef, $a) = Socket::unpack_sockaddr_in6($r->{addr});
            $ip = Socket::inet_ntop(Socket::AF_INET6(), $a);
        }
        push(@ips, $ip) if (defined($ip) && !$seen{$ip}++);
    }
    return @ips;
}

# File mtime on the same scale as log_time_epoch (local wall clock as UTC).
sub local_epoch_of {
    my ($t) = @_;
    require Time::Local;
    my @l = localtime($t);
    return Time::Local::timegm(@l[0 .. 5]);
}

sub is_loopback_ip {
    my ($ip) = @_;
    return ip_in_ranges($ip, [ map { cidr_parse($_) } ('127.0.0.0/8', '::1/128') ]);
}

# Everything the Cloudflare page checks. Options: live => ask the Cloudflare
# API for its current ranges; dns => resolve each site's name.
# Returns a hash with checks => [ { id, state (ok|warn|bad|na), title,
# detail (HTML), fix (action name or '') } ], ready, sites, ranges, ...
sub cloudflare_readiness {
    my (%o) = @_;
    my (%r, @checks);
    my $e = sub { &html_escape(join('', @_)) };
    my $loc = sub { my ($d) = @_; "<span class='msm-path'>" . $e->("$d->{file}:$d->{line}") . "</span>" };

    my ($ranges, $src, $rerr) = cf_ip_ranges($o{live});
    my @cf = grep { $_ } map { cidr_parse($_) } @$ranges;
    @r{qw(ranges range_source range_error)} = ($ranges, $src, $rerr);

    # 1. Can this server talk to the Cloudflare API?
    if ($o{live}) {
        push(@checks, { id => 'api', title => 'Cloudflare API reachable',
            state => $src eq 'live' ? 'ok' : 'bad', fix => '',
            detail => $src eq 'live'
                ? "Fetched Cloudflare's current address ranges from api.cloudflare.com."
                : "Could not reach api.cloudflare.com: " . $e->($rerr) .
                  ". Blocking needs outbound HTTPS from this server (HTTP::Tiny with IO::Socket::SSL, or curl)." });
    }

    # 2. mod_remoteip loaded.
    my $mod = apache_module_loaded('remoteip');
    my @dir = remoteip_directives();
    my @headers = grep { $_->{directive} eq 'remoteipheader' } @dir;
    my @foreign = grep { !is_managed_realip_file($_->{file}) } @headers;
    my $plan = cf_migration_plan(\@dir, \@cf);
    my $can_fix = !@foreign || $plan->{ok} ? 'realip' : '';
    $r{migration} = $plan;
    $r{managed} = -e cf_realip_conf_file() ? 1 : 0;
    $r{managed_on} = -e cf_realip_conf_link() ? 1 : 0;
    push(@checks, { id => 'module', title => 'Apache mod_remoteip enabled',
        state => $mod ? 'ok' : 'bad', fix => $mod ? '' : $can_fix,
        detail => $mod ? "The <b>remoteip</b> module is loaded."
                       : "The <b>remoteip</b> module is not loaded, so Apache and ModSecurity only see Cloudflare's address." });

    # 3. RemoteIPHeader CF-Connecting-IP.
    my @global = grep { !$_->{vhost} } @headers;
    my ($hstate, $hdetail);
    if (!@headers) {
        ($hstate, $hdetail) = ('bad', "No <code>RemoteIPHeader</code> is set. Cloudflare sends the visitor's address in " .
                                      "<code>CF-Connecting-IP</code>; Apache has to be told to use it.");
    } else {
        my $h = $global[-1] || $headers[-1];
        my $name = (split(/\s+/, $h->{args}))[0] || '';
        if (lc($name) eq 'cf-connecting-ip') {
            ($hstate, $hdetail) = ('ok', "<code>RemoteIPHeader CF-Connecting-IP</code> in " . $loc->($h) . ".");
        } elsif (lc($name) eq 'x-forwarded-for') {
            ($hstate, $hdetail) = ('warn', "<code>RemoteIPHeader X-Forwarded-For</code> in " . $loc->($h) .
                ". This works with Cloudflare, but <code>CF-Connecting-IP</code> is the header Cloudflare recommends.");
        } else {
            ($hstate, $hdetail) = ('bad', "<code>RemoteIPHeader " . $e->($name) . "</code> in " . $loc->($h) .
                ". Cloudflare does not send this header; use <code>CF-Connecting-IP</code>.");
        }
        if (!@global && $hstate ne 'bad') {
            $hstate = 'warn';
            $hdetail .= " It is only set inside <code>&lt;VirtualHost&gt;</code> blocks, so other sites still log Cloudflare's address.";
        }
    }
    push(@checks, { id => 'header', title => 'Real-IP header is CF-Connecting-IP', state => $hstate,
                    detail => $hdetail, fix => $hstate eq 'ok' ? '' : $can_fix });

    # 4. Header accepted only from Cloudflare.
    my (@trusted, @unparsed, @wide);
    foreach my $d (grep { $_->{directive} =~ /proxy/ } @dir) {
        my @items;
        if ($d->{directive} =~ /list$/) {
            my $f = $d->{args};
            $f =~ s/^["']|["']$//g;
            $f = apache_root() . "/$f" if ($f !~ m#^/#);
            foreach my $l (split(/\n/, read_text_file($f))) {
                $l =~ s/#.*$//;
                push(@items, split(/\s+/, $l));
            }
        } else {
            @items = split(/\s+/, $d->{args});
        }
        foreach my $i (grep { $_ ne '' } @items) {
            my $c = cidr_parse($i);
            if (!$c) { push(@unparsed, $i); next; }
            push(@trusted, $c);
            push(@wide, $i) if ($c->{len} < (length($c->{net}) == 4 ? 8 : 16));
        }
    }
    my @missing = grep { my $cf = $_; !grep { cidr_contains($_, $cf) } @trusted } @cf;
    $r{missing_ranges} = [ map { $_->{text} } @missing ];
    my ($tstate, $tdetail);
    if (@wide) {
        ($tstate, $tdetail) = ('bad', "Trusted proxies include " . $e->(join(', ', @wide)) .
            ", which lets almost any client set its own address. Trust only Cloudflare's ranges.");
    } elsif (!@trusted && !@unparsed) {
        ($tstate, $tdetail) = ('bad', "No <code>RemoteIPTrustedProxy</code> is set. " . (@headers
            ? "mod_remoteip then accepts the header from any client, so an attacker could fake " .
              "<code>CF-Connecting-IP</code> and get someone else's address blocked."
            : "Cloudflare's ranges must be trusted, and only them, so nobody else can fake the visitor's address."));
    } elsif (@missing) {
        ($tstate, $tdetail) = ('warn', scalar(@missing) . " of " . scalar(@cf) . " Cloudflare ranges are not trusted (" .
            $e->(join(', ', map { $_->{text} } @missing[0 .. ($#missing < 3 ? $#missing : 3)])) .
            (@missing > 4 ? ', ...' : '') . "). Visitors arriving through them are logged with Cloudflare's address.");
    } else {
        ($tstate, $tdetail) = ('ok', "All " . scalar(@cf) . " Cloudflare ranges are trusted" .
            (@unparsed ? "; host names that could not be checked: " . $e->(join(', ', @unparsed)) : "") . ".");
    }
    push(@checks, { id => 'trusted', title => 'Header accepted from Cloudflare only', state => $tstate,
                    detail => $tdetail, fix => $tstate eq 'ok' ? '' : $can_fix });

    # 5. Does the audit log actually hold visitor addresses? Events logged
    # before the real-IP config last changed do not count.
    my (undef, $txs, $file, $lerr) = read_recent_log('audit');
    my $since = 0;
    foreach my $d (@dir) {
        my $m = (stat($d->{file}))[9];
        $since = local_epoch_of($m) if ($m && local_epoch_of($m) > $since);
    }
    my ($n, $from_cf, $from_lo, $last_cf) = (0, 0, 0, '');
    foreach my $tx (@$txs) {
        my $t = log_time_epoch($tx->{time});
        next if ($since && (!defined($t) || $t <= $since));
        my $c = $tx->{client} || next;
        $n++;
        if (ip_in_ranges($c, \@cf)) { $from_cf++; $last_cf ||= $c; }
        $from_lo++ if (is_loopback_ip($c));
    }
    my ($lstate, $ldetail);
    if (!$n) {
        ($lstate, $ldetail) = ('na', $lerr ? $e->($lerr) :
            "No audit log events" . ($since ? " since the real-IP settings last changed" : "") .
            " yet. This check runs once ModSecurity logs a request.");
    } elsif ($from_cf) {
        ($lstate, $ldetail) = ('bad', "A Cloudflare address appears in $from_cf of the last " . plural($n, "event") . " (for example " .
            $e->($last_cf) . "). ModSecurity is seeing Cloudflare, not the visitor" .
            ($since ? "; if you just changed the config, reload Apache" : "") . ".");
    } elsif ($from_lo * 2 > $n) {
        ($lstate, $ldetail) = ('warn', "127.0.0.1 appears in $from_lo of the last " . plural($n, "event") . ". With a Cloudflare Tunnel or a local " .
            "proxy, add its address to the trusted proxies so the visitor's address is used.");
    } else {
        ($lstate, $ldetail) = ('ok', "None of the last " . plural($n, "event") . " came from a Cloudflare address.");
    }
    push(@checks, { id => 'log', title => 'ModSecurity logs real visitor addresses', state => $lstate,
                    detail => $ldetail, fix => '' });

    # 6. Which sites are proxied by Cloudflare?
    my @sites;
    if ($o{dns}) {
        my $count = 0;
        foreach my $v (apache_vhosts()) {
            my $name = $v->{name};
            next if ($name !~ /\./ || $name =~ /[*?]/ || defined(ip_pack($name)) || $name =~ /(?:^|\.)localhost$/);
            last if (++$count > 40);
            my @ips = resolve_host($name);
            my $on = grep { ip_in_ranges($_, \@cf) } @ips;
            push(@sites, { name => $name, ips => \@ips,
                           state => !@ips ? 'none' : $on == @ips ? 'proxied' : $on ? 'mixed' : 'direct' });
        }
        my $prox = grep { $_->{state} ne 'direct' && $_->{state} ne 'none' } @sites;
        my $dir_n = grep { $_->{state} eq 'direct' } @sites;
        push(@checks, { id => 'sites', title => 'Sites proxied through Cloudflare', fix => '',
            state => !@sites ? 'na' : $prox ? 'ok' : 'warn',
            detail => !@sites ? "No sites with a public name were found in the enabled Apache sites."
                    : $prox ? "$prox of " . scalar(@sites) . " sites resolve to Cloudflare." .
                              ($dir_n ? " $dir_n go straight to this server; Cloudflare blocks do not protect them." : "")
                    : "None of the " . scalar(@sites) . " sites resolve to Cloudflare. Blocking at Cloudflare only stops " .
                      "traffic to proxied (orange cloud) sites; use the server firewall for the others." });
    }
    $r{sites} = \@sites;

    $r{checks} = \@checks;
    my %need = map { $_ => 1 } qw(api module header trusted log);
    $r{blocking} = [ grep { $need{$_->{id}} && $_->{state} eq 'bad' } @checks ];
    $r{ready} = !@{$r{blocking}} && !grep { $_->{id} =~ /^(?:sites|log)$/ && $_->{state} ne 'ok' } @checks;
    $r{can_fix} = $can_fix;
    $r{foreign_headers} = \@foreign;
    $r{directives} = \@dir;
    return %r;
}

# Write the managed conf snippet (RemoteIPHeader CF-Connecting-IP and every
# Cloudflare range as a trusted proxy), enable remoteip and the snippet, and
# test the config. Cloudflare real-IP settings found in other files (such as
# a VirtualHost) are moved into the snippet first. Everything this changed
# is undone if the test fails.
# Returns ($ok, \@steps, $message); each step is [title, code, output].
sub cf_setup_realip {
    my %p = paths();
    my @steps;
    my ($ranges, $src, $err) = cf_ip_ranges(1);
    my @cf = grep { $_ } map { cidr_parse($_) } @$ranges;
    my @dirs = remoteip_directives();
    my @foreign = grep { $_->{directive} eq 'remoteipheader' && !is_managed_realip_file($_->{file}) } @dirs;
    my $plan = cf_migration_plan(\@dirs, \@cf);
    return (0, [], $plan->{reason} || "A RemoteIPHeader is already set in another file.") if (@foreign && !$plan->{ok});
    my $file = cf_realip_conf_file();
    -d File::Basename::dirname($file) || return (0, [], "Directory not found: " . File::Basename::dirname($file));

    # Move settings out of other files: back each file up, then comment out.
    my @moved;   # [real path, backup]
    if ($plan->{ok}) {
        my %by;
        push(@{$by{$_->{file}}}, $_) foreach (@{$plan->{edits}});
        foreach my $f (sort keys %by) {
            my $real = Cwd::abs_path($f) || $f;
            my $bk = backup_file($real);
            push(@moved, [$real, $bk]);
            comment_out_remoteip_lines($real, [ map { $_->{line} } @{$by{$f}} ]);
            push(@steps, ["Commented out " . plural(scalar(@{$by{$f}}), 'line') . " in $f", 0,
                          join('', map { "line $_->{line}: $_->{args}\n" } @{$by{$f}}) . "Backup: $bk\n"]);
        }
        push(@steps, ["Kept " . plural(scalar(@{$plan->{carry}}), 'other trusted proxy setting'), 0,
                      join("\n", @{$plan->{carry}}) . "\n"]) if (@{$plan->{carry}});
        push(@steps, ["Dropped ranges that trusted almost every address", 0, join("\n", @{$plan->{dropped}}) . "\n"])
            if (@{$plan->{dropped}});
    }

    my $existed = -e $file;
    my $backup = $existed ? backup_file($file) : undef;
    write_text_file($file, cf_realip_conf_text($ranges, $plan->{ok} ? $plan->{carry} : []), 0644);
    push(@steps, ["Wrote $file (" . scalar(@$ranges) . " Cloudflare ranges, $src list)", 0,
                  $err ? "Live list not available ($err); used the $src list.\n" : '']);

    my ($mod_added, $conf_added, $fail) = (0, 0, 0);
    if (!apache_module_loaded('remoteip')) {
        my ($c, $o) = run_command_list($p{a2enmod}, 'remoteip');
        push(@steps, ['a2enmod remoteip', $c, $o]);
        $c == 0 ? ($mod_added = 1) : ($fail = 1);
    }
    if (!$fail && !-e cf_realip_conf_link()) {
        my ($c, $o) = run_command_list($p{a2enconf}, cf_realip_conf_name());
        push(@steps, ['a2enconf ' . cf_realip_conf_name(), $c, $o]);
        $c == 0 ? ($conf_added = 1) : ($fail = 1);
    }
    if (!$fail) {
        my ($c, $o) = apache_configtest();
        push(@steps, ['Apache config test', $c, $o]);
        $fail = 1 if ($c != 0);
    }
    if ($fail) {
        push(@steps, ['Rollback: a2disconf ' . cf_realip_conf_name(), run_command_list($p{a2disconf}, cf_realip_conf_name())])
            if ($conf_added);
        push(@steps, ['Rollback: a2dismod remoteip', run_command_list($p{a2dismod}, 'remoteip')]) if ($mod_added);
        $existed ? restore_backup($file, $backup) : remove_created_file($file);
        restore_backup(@$_) foreach (@moved);
        push(@steps, ["Rollback: restored " . plural(scalar(@moved), 'file') . " the settings were moved from", 0, ''])
            if (@moved);
        return (0, \@steps, "Setup failed and every change was undone. See the output below.");
    }
    return (1, \@steps, "Real visitor addresses are configured for every site" .
                        (@moved ? ", and the old settings in " . plural(scalar(@moved), 'file') . " were commented out" : "") .
                        ". Reload Apache to apply, then wait for new requests before checking the audit log again.");
}

# ---------------------------------------------------------------------------
# AI crawlers
# ---------------------------------------------------------------------------
# A managed ModSecurity rule file that blocks (or only logs) AI crawlers by
# the User-Agent token they publish. Honest crawlers are stopped this way;
# a scraper that pretends to be a browser is not, and CRS still handles
# scanners by behaviour. Tokens that exist only in robots.txt (such as
# Google-Extended and Applebot-Extended) never appear in a User-Agent, so
# they are not listed here.

# [token, owner, group]. Tokens are matched case-insensitively anywhere in
# the User-Agent (ModSecurity @pm), so they must not contain spaces.
my @AI_BOTS = (
    ['GPTBot',                       'OpenAI',          'training'],
    ['ClaudeBot',                    'Anthropic',       'training'],
    ['anthropic-ai',                 'Anthropic (older)', 'training'],
    ['Claude-Web',                   'Anthropic (older)', 'training'],
    ['CCBot',                        'Common Crawl',    'training'],
    ['Bytespider',                   'ByteDance',       'training'],
    ['Meta-ExternalAgent',           'Meta',            'training'],
    ['FacebookBot',                  'Meta',            'training'],
    ['Amazonbot',                    'Amazon',          'training'],
    ['cohere-training-data-crawler', 'Cohere',          'training'],
    ['cohere-ai',                    'Cohere',          'training'],
    ['Diffbot',                      'Diffbot',         'training'],
    ['AI2Bot',                       'Allen Institute', 'training'],
    ['omgili',                       'Webz.io',         'training'],
    ['ImagesiftBot',                 'ImageSift',       'training'],
    ['Timpibot',                     'Timpi',           'training'],
    ['PanguBot',                     'Huawei',          'training'],
    ['img2dataset',                  'Dataset tool',    'training'],
    ['OAI-SearchBot',                'OpenAI',          'search'],
    ['Claude-SearchBot',             'Anthropic',       'search'],
    ['PerplexityBot',                'Perplexity',      'search'],
    ['YouBot',                       'You.com',         'search'],
    ['DuckAssistBot',                'DuckDuckGo',      'search'],
    ['ChatGPT-User',                 'OpenAI',          'user'],
    ['Claude-User',                  'Anthropic',       'user'],
    ['Perplexity-User',              'Perplexity',      'user'],
    ['MistralAI-User',               'Mistral',         'user'],
    ['Meta-ExternalFetcher',         'Meta',            'user'],
    ['Google-CloudVertexBot',        'Google',          'user'],
);

sub ai_bot_catalog {
    return map { { token => $_->[0], owner => $_->[1], group => $_->[2] } } @AI_BOTS;
}

sub ai_bot_groups {
    return (
        ['training', 'Training crawlers', 'Collect pages to train AI models. Blocking them does not affect search engines.'],
        ['search',   'AI search crawlers', 'Index pages for AI search and answers. Blocking them removes the site from those results.'],
        ['user',     'Fetches for a user', 'An assistant opening a page because someone asked it to, like a browser would.'],
    );
}

# Rule ids 1100100-1100109 are reserved for this file (custom exclusions use
# 1000000-1099999).
sub ai_bots_rule_id { return 1100103; }

sub ai_bot_settings {
    my %known = map { lc($_->[0]) => $_->[0] } @AI_BOTS;
    my $list = cfg('ai_bots_list', join(',', map { $_->[0] } grep { $_->[2] eq 'training' } @AI_BOTS));
    return (
        enabled => cfg('ai_bots_enabled', 0) ? 1 : 0,
        mode    => cfg('ai_bots_mode', 'block') eq 'log' ? 'log' : 'block',
        bots    => [ grep { $_ } map { $known{lc($_)} } split(/\s*,\s*/, $list) ],
        allow   => [ grep { /^[a-z0-9*.-]+$/ } split(/\s*,\s*/, lc(cfg('ai_bots_allow_sites', ''))) ],
        robots  => cfg('ai_bots_robots', 1) ? 1 : 0,
        file    => cfg('ai_bots_file', '/etc/modsecurity/modsec-ai-bots.conf'),
    );
}

# Regex for Host headers of the given site names (aliases with * allowed).
sub host_regex {
    my @names = @_;
    my @alt;
    foreach my $n (@names) {
        my $re = quotemeta(lc($n));
        $re =~ s/\\\*/[a-z0-9.-]*/g;
        push(@alt, $re);
    }
    return "^(?:" . join('|', @alt) . ")(?::[0-9]+)?\$";
}

# The managed rule file. %s is ai_bot_settings(); $hosts are the Host names
# (with aliases) of the sites left open to AI crawlers.
sub ai_bots_rule_text {
    my ($s, $hosts) = @_;
    my $t = "# AI crawler blocking.\n" .
            "# Managed by Webmin ModSecurity Manager (AI bots page); changes here are overwritten.\n" .
            "# Rule ids 1100100-1100109 are reserved for this file.\n\n";
    if ($s->{robots}) {
        $t .= "# Let crawlers read robots.txt, so well-behaved ones learn they are not welcome.\n" .
              "SecRule REQUEST_FILENAME \"\@streq /robots.txt\" \\\n" .
              "    \"id:1100101,phase:1,pass,nolog,t:none,skipAfter:MSM_AI_BOTS_END\"\n\n";
    }
    if (@$hosts) {
        $t .= "# Sites left open to AI crawlers.\n" .
              "SecRule REQUEST_HEADERS:Host \"\@rx " . host_regex(@$hosts) . "\" \\\n" .
              "    \"id:1100102,phase:1,pass,nolog,t:none,t:lowercase,skipAfter:MSM_AI_BOTS_END\"\n\n";
    }
    my $action = $s->{mode} eq 'log'
        ? "pass,log,auditlog,msg:'AI crawler detected'"
        : "deny,status:403,log,auditlog,msg:'AI crawler blocked'";
    $t .= "SecRule REQUEST_HEADERS:User-Agent \"\@pm " . join(' ', @{$s->{bots}}) . "\" \\\n" .
          "    \"id:" . ai_bots_rule_id() . ",phase:1,$action,t:none,severity:'NOTICE',\\\n" .
          "    logdata:'%{MATCHED_VAR}',tag:'modsec-manager/ai-bots'\"\n\n" .
          "SecMarker MSM_AI_BOTS_END\n";
    return $t;
}

# Host names (ServerName and ServerAlias) of the given enabled sites.
sub site_host_names {
    my %want = map { $_ => 1 } @_;
    my @h;
    foreach my $v (apache_vhosts()) {
        next if (!$want{$v->{name}});
        push(@h, $v->{name}, @{$v->{aliases}});
    }
    my %seen;
    return grep { !$seen{$_}++ } @h;
}

# Is $file loaded by ModSecurity (directly or through a glob such as
# IncludeOptional /etc/modsecurity/*.conf)?
sub modsec_file_included {
    my ($file) = @_;
    my %p = paths();
    return line_includes_file(read_text_file($p{apache_security_conf}), $file) ||
           line_includes_file(read_text_file($p{modsecurity_conf}), $file);
}

# Write (or, when turned off, remove) the rule file and test the config.
# Everything is put back if the test fails.
# Returns ($code, $output, \@notes, $text).
sub apply_ai_bots {
    my (%s) = @_;
    my %p = paths();
    my $file = $s{file};
    my @notes;
    if (!$s{enabled}) {
        return (0, '', ["The rule file was not there; nothing to remove."], '') if (!-e $file);
        my $backup = backup_file($file);
        unlink($file) || fail("Cannot remove $file: $!");
        my ($code, $out) = apache_configtest();
        if ($code != 0) {
            restore_backup($file, $backup);
            push(@notes, "Config test failed, so $file was put back.");
        } else {
            push(@notes, "Removed $file (backup: $backup).");
        }
        return ($code, $out, \@notes, '');
    }
    -d File::Basename::dirname($file) || fail("Directory not found: " . File::Basename::dirname($file));
    my $text = ai_bots_rule_text(\%s, [ site_host_names(@{$s{allow}}) ]);
    my ($inc_backup, $inc_added);
    if (!modsec_file_included($file)) {
        -e $p{modsecurity_conf} || fail("$p{modsecurity_conf} does not exist");
        my $data = read_text_file($p{modsecurity_conf});
        $inc_backup = backup_file($p{modsecurity_conf});
        $data .= "\n" if ($data ne '' && substr($data, -1) ne "\n");
        write_text_file($p{modsecurity_conf}, $data . "\n# AI crawler rules managed by Webmin\nIncludeOptional $file\n", 0644);
        push(@notes, "Added IncludeOptional $file to $p{modsecurity_conf}.");
        $inc_added = 1;
    }
    my ($code, $out, $backup, $reverted) = save_file_with_configtest($file, $text);
    if ($code != 0) {
        restore_backup($p{modsecurity_conf}, $inc_backup) if ($inc_added);
        push(@notes, "Config test failed, so the change was undone.");
    } else {
        push(@notes, "Wrote $file" . ($backup ? " (backup: $backup)" : "") . ".");
    }
    return ($code, $out, \@notes, $text);
}

# AI crawler hits in the audit log, by bot token:
# { token => { count, blocked, last, hosts => { host => n } } }.
sub ai_bot_hits {
    my ($txs) = @_;
    my $id = ai_bots_rule_id();
    my @tokens = map { $_->[0] } @AI_BOTS;
    my %hits;
    foreach my $tx (@$txs) {
        my ($m) = grep { ($_->{id} || '') eq $id } @{$tx->{messages}};
        next if (!$m);
        my $ua = lc($m->{data} || '');
        my ($tok) = grep { index($ua, lc($_)) >= 0 } @tokens;
        my $h = $hits{$tok || 'Other'} ||= { count => 0, blocked => 0, last => '', hosts => {} };
        $h->{count}++;
        $h->{blocked}++ if (tx_blocked($tx));
        $h->{last} ||= $tx->{time} || '';
        $h->{hosts}{norm_host($tx->{host})}++ if ($tx->{host});
    }
    return \%hits;
}

# ---------------------------------------------------------------------------
# Blocking attacker addresses
# ---------------------------------------------------------------------------
# One block can go to three places:
#  - cloudflare: an account-level IP Access Rule, so requests are refused at
#    Cloudflare's edge for every proxied site in the account;
#  - modsec: a deny rule that reads a list of addresses. It works for proxied
#    and direct traffic alike, because mod_remoteip hands ModSecurity the
#    visitor's address. Apache is reloaded to pick up a changed list;
#  - ufw: a deny rule for all ports. The firewall only sees the address that
#    connects, so it stops direct connections, not traffic via Cloudflare.
# Blocks are recorded in blocks.json in the module config directory. Blocks
# with an end time are lifted by block_expire.pl from cron.

# Never blocked: private, loopback, link-local, CGNAT, multicast/reserved.
my @NEVER_BLOCK = qw(0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12
                     192.168.0.0/16 224.0.0.0/3 ::/128 ::1/128 fc00::/7 fe80::/10 ff00::/8);

sub block_target_names {
    return (cloudflare => 'Cloudflare', modsec => 'ModSecurity', ufw => 'ufw firewall');
}

sub block_settings {
    my $mode = cfg('block_cf_mode', 'block');
    my $dur = cfg('block_duration', 24);
    return (
        cf_token   => cfg('block_cf_token', ''),
        cf_account => cfg('block_cf_account', ''),
        cf_mode    => $mode =~ /^(?:block|managed_challenge)$/ ? $mode : 'block',
        targets    => [ grep { /^(?:cloudflare|modsec|ufw)$/ } split(/\s*,\s*/, cfg('block_targets', 'cloudflare,modsec')) ],
        duration   => $dur =~ /^\d+$/ ? $dur : 24,
        whitelist  => [ grep { cidr_parse($_) } split(/[\s,]+/, cfg('block_whitelist', '')) ],
        rule_file  => cfg('block_modsec_file', '/etc/modsecurity/modsec-ip-blocklist.conf'),
        data_file  => cfg('block_modsec_data', '/etc/modsecurity/modsec-ip-blocklist.txt'),
        ufw        => cfg('ufw', '/usr/sbin/ufw'),
        cron_file  => cfg('block_cron_file', '/etc/cron.d/webmin-modsec-manager-blocks'),
    );
}

# Why each target cannot be used right now ('' when it can).
sub block_target_problems {
    my (%s) = @_;
    return (
        cloudflare => !$s{cf_token} ? 'No Cloudflare API token yet (see Settings below)'
                    : $s{cf_account} !~ /^[0-9a-f]{32}$/ ? 'No Cloudflare account ID yet (see Settings below)' : '',
        modsec     => '',
        ufw        => -x $s{ufw} ? '' : "ufw is not installed ($s{ufw})",
    );
}

# Normalised text form of an address (lower case, IPv6 compressed), or undef.
sub ip_canonical {
    my ($ip) = @_;
    return undef if (!defined($ip) || $ip =~ m#/#);
    my $b = ip_pack($ip);
    return undef if (!defined($b));
    require Socket;
    return Socket::inet_ntop(length($b) == 4 ? Socket::AF_INET() : Socket::AF_INET6(), $b);
}

sub server_addresses {
    foreach my $h ('/usr/bin/hostname', '/bin/hostname') {
        next if (!-x $h);
        my ($code, $out) = run_command_list($h, '-I');
        return grep { defined } map { ip_canonical($_) } split(/\s+/, $out) if ($code == 0);
    }
    return ();
}

# Why $ip must not be blocked, or '' if it may be.
sub block_refusal {
    my ($ip, %s) = @_;
    return "Enter one IPv4 or IPv6 address (not a range)" if (!defined(ip_canonical($ip)));
    my $c = ip_canonical($ip);
    my ($cf) = cf_ip_ranges(0);
    return "$c is a Cloudflare address. Blocking it would cut off visitors who reach your sites through Cloudflare."
        if (ip_in_ranges($c, [ map { cidr_parse($_) } @$cf ]));
    return "$c is a private, loopback or reserved address." if (ip_in_ranges($c, [ map { cidr_parse($_) } @NEVER_BLOCK ]));
    return "$c is one of this server's own addresses." if (grep { $_ eq $c } server_addresses());
    my $me = ip_canonical($ENV{'REMOTE_ADDR'});
    return "$c is the address you are using Webmin from." if ($me && $me eq $c);
    return "$c is on the never-block list." if (ip_in_ranges($c, [ map { cidr_parse($_) } @{$s{whitelist}} ]));
    return '';
}

sub blocks_file {
    return ($module_config_directory || "/etc/webmin/modsec-manager") . "/blocks.json";
}

# List of { ip, reason, by, added, expires (0 = never), targets => {
#   cloudflare => { id, preexisting }, modsec => 1, ufw => 1 } }.
sub read_blocks {
    my $d = read_text_file(blocks_file());
    return [] if ($d !~ /\S/);
    my $j = eval { require JSON::PP; JSON::PP->new->decode($d) };
    return ref($j) eq 'ARRAY' ? [ grep { ref($_) eq 'HASH' && defined(ip_canonical($_->{ip})) } @$j ] : [];
}

sub write_blocks {
    my ($list) = @_;
    require JSON::PP;
    write_text_file(blocks_file(), JSON::PP->new->canonical->pretty->encode($list), 0600);
}

# --- Cloudflare ---------------------------------------------------------------

# Call the Cloudflare API. Returns ($ok, $json, $error, \@error_codes).
sub cf_api {
    my ($method, $path, $body, %s) = @_;
    require JSON::PP;
    my $json = defined($body) ? JSON::PP->new->canonical->encode($body) : undef;
    my ($ok, $content, $err, $status) = https_request($method, "https://api.cloudflare.com/client/v4$path",
        { 'Authorization' => "Bearer $s{cf_token}", (defined($json) ? ('Content-Type' => 'application/json') : ()) }, $json);
    my $j = eval { JSON::PP->new->decode($content || '') };
    if (ref($j) eq 'HASH') {
        my @e = grep { ref($_) eq 'HASH' } (ref($j->{errors}) eq 'ARRAY' ? @{$j->{errors}} : ());
        my $msg = join('; ', map { ($_->{message} || 'error') . ($_->{code} ? " (code $_->{code})" : '') } @e);
        return (1, $j, '', []) if ($j->{success});
        return (0, $j, $msg || $err || "HTTP $status", [ map { $_->{code} || 0 } @e ]);
    }
    return (0, undef, $err || "Unexpected answer from the Cloudflare API", []);
}

sub cf_rules_path {
    my (%s) = @_;
    return "/accounts/$s{cf_account}/firewall/access_rules/rules";
}

# Account ID when the token sees exactly one account. Returns ($id, $message).
sub cf_detect_account {
    my (%s) = @_;
    my ($ok, $j, $err) = cf_api('GET', '/accounts?per_page=5', undef, %s);
    return (undef, "Could not list accounts: $err") if (!$ok);
    my @a = grep { ref($_) eq 'HASH' && ($_->{id} || '') =~ /^[0-9a-f]{32}$/ } (ref($j->{result}) eq 'ARRAY' ? @{$j->{result}} : ());
    return (undef, "The token cannot see any account. Enter the account ID by hand.") if (!@a);
    return (undef, "The token can see " . scalar(@a) . " accounts. Enter the account ID by hand.") if (@a > 1);
    return ($a[0]{id}, "Found account " . ($a[0]{name} || $a[0]{id}) . ".");
}

sub cf_test_connection {
    my (%s) = @_;
    my ($ok, $j, $err) = cf_api('GET', cf_rules_path(%s) . '?per_page=1', undef, %s);
    return (0, "Cloudflare refused the request: $err") if (!$ok);
    my $n = ref($j->{result_info}) eq 'HASH' ? ($j->{result_info}{total_count} || 0) : 0;
    return (1, "Connected. The token can read this account's IP Access Rules ($n now).");
}

# Returns ($ok, $rule_id, $message, $preexisting).
sub cf_block_ip {
    my ($ip, $note, %s) = @_;
    my $target = index($ip, ':') >= 0 ? 'ip6' : 'ip';
    my ($ok, $j, $err, $codes) = cf_api('POST', cf_rules_path(%s),
        { mode => $s{cf_mode}, configuration => { target => $target, value => $ip }, notes => $note }, %s);
    if ($ok && ref($j->{result}) eq 'HASH' && $j->{result}{id}) {
        return (1, $j->{result}{id}, ($s{cf_mode} eq 'block' ? "Blocked" : "Managed challenge") .
                                     " for every proxied site in the account", 0);
    }
    if ((grep { $_ == 10009 } @$codes) || $err =~ /duplicate|already exists/i) {
        my ($fok, $fj) = cf_api('GET', cf_rules_path(%s) . "?configuration.target=$target&configuration.value=" .
                                url_escape($ip), undef, %s);
        my ($r) = $fok && ref($fj->{result}) eq 'ARRAY' ? @{$fj->{result}} : ();
        return (1, $r->{id}, "A rule for this address already existed (mode " . ($r->{mode} || '?') .
                             "); it is left in place when you unblock", 1) if ($r && $r->{id});
    }
    return (0, undef, $err, 0);
}

sub cf_unblock_ip {
    my ($t, %s) = @_;
    return (1, "Left the rule that existed before") if ($t->{preexisting});
    return (1, "No rule to remove") if (($t->{id} || '') !~ /^[0-9a-f]{32}$/);
    my ($ok, $j, $err) = cf_api('DELETE', cf_rules_path(%s) . "/$t->{id}", undef, %s);
    return (1, "Rule removed") if ($ok);
    return (1, "Rule was already gone") if ($err =~ /not found|HTTP 404|code 10007/i);
    return (0, $err);
}

# --- ModSecurity ----------------------------------------------------------------

sub modsec_block_rule_text {
    my (%s) = @_;
    return "# Blocked addresses.\n" .
           "# Managed by Webmin ModSecurity Manager (Blocked IPs page); changes here are overwritten.\n" .
           "# Rule ids 1100110-1100119 are reserved for this file. The addresses are in\n" .
           "# $s{data_file}, which is read when Apache starts or reloads.\n" .
           "SecRule REMOTE_ADDR \"\@ipMatchFromFile $s{data_file}\" \\\n" .
           "    \"id:1100110,phase:1,deny,status:403,log,auditlog,t:none,severity:'NOTICE',\\\n" .
           "    msg:'Address on the ModSecurity Manager blocklist',tag:'modsec-manager/ip-block'\"\n";
}

# Write the address list (and the rule file, or remove it when the list is
# empty), test the config and reload Apache. Puts everything back if the
# test fails. Returns ($ok, $message).
sub modsec_apply_blocks {
    my ($blocks, %s) = @_;
    my %p = paths();
    my @ips = sort map { $_->{ip} } grep { $_->{targets}{modsec} } @$blocks;
    my $data = join('', map { "$_\n" } @ips);
    my $rule = @ips ? modsec_block_rule_text(%s) : undef;
    my $old_data = -e $s{data_file} ? read_text_file($s{data_file}) : undef;
    my $old_rule = -e $s{rule_file} ? read_text_file($s{rule_file}) : undef;
    return (1, "Blocklist unchanged") if (($old_data // '') eq $data && ($old_rule // "\0") eq ($rule // "\0"));
    -d File::Basename::dirname($s{data_file}) || return (0, "Directory not found: " . File::Basename::dirname($s{data_file}));

    my ($inc_backup, $inc_added);
    write_text_file($s{data_file}, $data, 0644);
    if (defined($rule)) {
        write_text_file($s{rule_file}, $rule, 0644);
        if (!modsec_file_included($s{rule_file})) {
            my $conf = read_text_file($p{modsecurity_conf});
            $inc_backup = backup_file($p{modsecurity_conf});
            $conf .= "\n" if ($conf ne '' && substr($conf, -1) ne "\n");
            write_text_file($p{modsecurity_conf}, $conf . "\n# IP blocklist managed by Webmin\nIncludeOptional $s{rule_file}\n", 0644);
            $inc_added = 1;
        }
    } elsif (-e $s{rule_file}) {
        unlink($s{rule_file});
    }
    my ($code, $out) = apache_configtest();
    if ($code != 0) {
        defined($old_data) ? write_text_file($s{data_file}, $old_data, 0644) : unlink($s{data_file});
        defined($old_rule) ? write_text_file($s{rule_file}, $old_rule, 0644) : unlink($s{rule_file});
        restore_backup($p{modsecurity_conf}, $inc_backup) if ($inc_added);
        return (0, "Config test failed, so the blocklist was left as it was:\n$out");
    }
    my ($rc, $rout) = run_command_list($p{systemctl}, 'reload', 'apache2');
    return (0, "Blocklist saved, but reloading Apache failed:\n$rout") if ($rc != 0);
    return (1, scalar(@ips) . (@ips == 1 ? " address" : " addresses") . " on the blocklist; Apache reloaded");
}

# --- ufw ------------------------------------------------------------------------

sub ufw_block_ip {
    my ($ip, %s) = @_;
    my ($c, $o) = run_command_list($s{ufw}, 'prepend', 'deny', 'from', $ip, 'comment', 'modsec-manager');
    ($c, $o) = run_command_list($s{ufw}, 'insert', '1', 'deny', 'from', $ip, 'comment', 'modsec-manager')
        if ($c != 0 && $o =~ /prepend|invalid syntax/i);
    $o =~ s/\s+$//;
    return (0, $o || "ufw failed") if ($c != 0);
    my ($sc, $so) = run_command_list($s{ufw}, 'status');
    return (1, "Denied on all ports" . ($so =~ /Status:\s*active/i ? "" : " (ufw is not active, so the rule has no effect yet)"));
}

# Delete this module's deny rules for $ip, highest rule number first.
sub ufw_unblock_ip {
    my ($ip, %s) = @_;
    my ($c, $o) = run_command_list($s{ufw}, 'status', 'numbered');
    return (0, "ufw status failed: $o") if ($c != 0);
    my @nums;
    foreach my $l (split(/\n/, $o)) {
        my ($n) = $l =~ /^\[\s*(\d+)\]/;
        next if (!$n || $l !~ /#\s*modsec-manager\b/);
        push(@nums, $n) if (grep { defined(ip_canonical($_)) && ip_canonical($_) eq $ip } split(/\s+/, $l));
    }
    return (1, "No rule to remove") if (!@nums);
    foreach my $n (sort { $b <=> $a } @nums) {
        my ($dc, $do) = run_command_list($s{ufw}, '--force', 'delete', $n);
        return (0, "ufw delete $n failed: $do") if ($dc != 0);
    }
    return (1, "Removed " . plural(scalar(@nums), 'rule'));
}

# --- Block, unblock, expire ---------------------------------------------------

sub fmt_time {
    my ($t) = @_;
    return POSIX::strftime("%d %b %Y %H:%M", localtime($t));
}

# Block $ip on @$targets. Returns ($blocked_somewhere, \@results) where each
# result is [target, ok, message].
sub block_ip {
    my ($ip, $reason, $hours, $targets, $user) = @_;
    my %s = block_settings();
    my %bad = block_target_problems(%s);
    $ip = ip_canonical($ip);
    $reason = substr(defined($reason) ? $reason : '', 0, 200);
    $reason =~ s/[\r\n\t]+/ /g;
    &lock_file(blocks_file());
    my $list = read_blocks();
    my ($rec) = grep { $_->{ip} eq $ip } @$list;
    if (!$rec) {
        $rec = { ip => $ip, added => time(), targets => {} };
        push(@$list, $rec);
    }
    $rec->{reason} = $reason;
    $rec->{by} = $user || '';
    $rec->{expires} = $hours ? time() + $hours * 3600 : 0;
    my $note = "ModSecurity Manager: " . ($reason ne '' ? $reason : 'blocked') .
               ($hours ? " (until " . fmt_time($rec->{expires}) . ")" : "");
    my (@res, $modsec);
    foreach my $t (@$targets) {
        if ($rec->{targets}{$t}) {
            push(@res, [$t, 1, "Already blocked here"]);
        } elsif ($bad{$t}) {
            push(@res, [$t, 0, $bad{$t}]);
        } elsif ($t eq 'cloudflare') {
            my ($ok, $id, $msg, $pre) = cf_block_ip($ip, substr($note, 0, 500), %s);
            push(@res, [$t, $ok, $msg]);
            $rec->{targets}{cloudflare} = { id => $id, preexisting => $pre ? 1 : 0 } if ($ok);
        } elsif ($t eq 'ufw') {
            my ($ok, $msg) = ufw_block_ip($ip, %s);
            push(@res, [$t, $ok, $msg]);
            $rec->{targets}{ufw} = 1 if ($ok);
        } elsif ($t eq 'modsec') {
            $rec->{targets}{modsec} = 1;
            $modsec = 1;
        }
    }
    if ($modsec) {
        my ($ok, $msg) = modsec_apply_blocks($list, %s);
        push(@res, ['modsec', $ok, $msg]);
        delete($rec->{targets}{modsec}) if (!$ok);
    }
    @$list = grep { %{$_->{targets}} } @$list;
    write_blocks($list);
    &unlock_file(blocks_file());
    sync_block_cron(%s);
    return (%{$rec->{targets}} ? 1 : 0, \@res);
}

# Lift the blocks on @$ips everywhere. A block that cannot be removed from
# some target stays listed for that target. Returns \@results, each
# [ip, target, ok, message].
sub unblock_ips {
    my ($ips) = @_;
    my %s = block_settings();
    my %want = map { ip_canonical($_) => 1 } grep { defined(ip_canonical($_)) } @$ips;
    &lock_file(blocks_file());
    my $list = read_blocks();
    my (@res, @modsec);
    foreach my $rec (grep { $want{$_->{ip}} } @$list) {
        my $t = $rec->{targets};
        if ($t->{cloudflare}) {
            my ($ok, $msg) = cf_unblock_ip($t->{cloudflare}, %s);
            push(@res, [$rec->{ip}, 'cloudflare', $ok, $msg]);
            delete($t->{cloudflare}) if ($ok);
        }
        if ($t->{ufw}) {
            my ($ok, $msg) = -x $s{ufw} ? ufw_unblock_ip($rec->{ip}, %s) : (1, "ufw is no longer installed");
            push(@res, [$rec->{ip}, 'ufw', $ok, $msg]);
            delete($t->{ufw}) if ($ok);
        }
        if ($t->{modsec}) {
            delete($t->{modsec});
            push(@modsec, $rec);
        }
    }
    if (@modsec) {
        my ($ok, $msg) = modsec_apply_blocks($list, %s);
        if (!$ok) {
            $_->{targets}{modsec} = 1 foreach (@modsec);
        }
        push(@res, [join(', ', map { $_->{ip} } @modsec), 'modsec', $ok, $msg]);
    }
    @$list = grep { %{$_->{targets}} } @$list;
    write_blocks($list);
    &unlock_file(blocks_file());
    sync_block_cron(%s);
    return \@res;
}

# Lift every block whose end time has passed. Returns \@results.
sub expire_blocks {
    my $now = time();
    my @due = map { $_->{ip} } grep { $_->{expires} && $_->{expires} <= $now } @{read_blocks()};
    return [] if (!@due);
    return unblock_ips(\@due);
}

# Cron job that lifts expired blocks; only installed while a block has an end time.
sub sync_block_cron {
    my (%s) = @_;
    if (!grep { $_->{expires} } @{read_blocks()}) {
        unlink($s{cron_file}) if (-e $s{cron_file});
        return;
    }
    my $root = $module_root_directory || Cwd::getcwd();
    my $cfgdir = $config_directory || '/etc/webmin';
    my $var = $var_directory || '/var/webmin';
    my $line = "# Lift expired IP blocks, managed by Webmin ModSecurity Manager\n" .
               "*/10 * * * * root cd $root && WEBMIN_CONFIG=$cfgdir WEBMIN_VAR=$var /usr/bin/perl $root/block_expire.pl >/dev/null 2>&1\n";
    write_text_file($s{cron_file}, $line, 0644) if (read_text_file($s{cron_file}) ne $line);
}

# ---------------------------------------------------------------------------
# Logs page filters and export
# ---------------------------------------------------------------------------

# Logs page filters from form input. Returns ($source, \%filters).
sub logs_filters {
    my ($in) = @_;
    my $source = ($in->{'source'} || '') eq 'error' ? 'error' : 'audit';
    my %f;
    foreach my $k ('rule', 'ip', 'host', 'path', 'site') {
        $f{$k} = defined($in->{$k}) ? $in->{$k} : '';
        $f{$k} =~ s/[\r\n]//g;
    }
    $f{blocked} = $in->{'blocked'} ? 1 : 0;
    $f{history} = ($in->{'history'} || 0) =~ /^([0-7])$/ ? $1 : 0;
    return ($source, \%f);
}

# Events matching the filters. A site filter matches its ServerName and
# every ServerAlias. Returns ($raw_lines, $all_txs, $file, $error, \@txs, \@vhosts).
sub logs_select {
    my ($source, $f) = @_;
    my ($raw, $all, $file, $err) = read_recent_log($source, $f->{history});
    my @vhosts = apache_vhosts();
    my $site_hosts;
    if ($f->{site} ne '') {
        my ($v) = grep { $_->{name} eq norm_host($f->{site}) } @vhosts;
        $site_hosts = { map { $_ => 1 } ($v ? ($v->{name}, grep { !/[*?]/ } @{$v->{aliases}}) : norm_host($f->{site})) };
    }
    my @txs = filter_transactions($all, %$f, hosts => $site_hosts);
    return ($raw, $all, $file, $err, \@txs, \@vhosts);
}

# One CSV field. Values starting with = + - @ (attacker-controlled URIs and
# headers) are prefixed with ' so spreadsheets do not run them as formulas.
sub csv_field {
    my ($v) = @_;
    $v = '' if (!defined($v));
    $v =~ s/[\r\n]+/ /g;
    $v = "'$v" if ($v =~ /^[=+\-\@\t]/ && length($v) > 1);
    return $v =~ /[",;\s]/ || $v eq '' ? '"' . join('""', split(/"/, $v, -1)) . '"' : $v;
}

# Events as CSV text (UTF-8 with a byte order mark, for Excel).
sub events_csv {
    my ($txs, $vhosts) = @_;
    my @cols = ('Time', 'Transaction', 'Client IP', 'Host', 'Site', 'Method', 'URI', 'Status', 'Blocked',
                'Rule IDs', 'Messages', 'Matched data');
    my $out = "\xEF\xBB\xBF" . join(',', map { csv_field($_) } @cols) . "\r\n";
    foreach my $tx (@$txs) {
        my ($method, $uri) = ($tx->{request} || '') =~ /^([A-Z]+)\s+(\S+)/ ? ($1, $2) : ('', $tx->{request} || '');
        my @m = grep { !is_score_rule($_->{id} || '') } @{$tx->{messages}};
        @m = @{$tx->{messages}} if (!@m);
        my %seen;
        my @ids = grep { $_ ne '' && !$seen{$_}++ } map { $_->{id} || '' } @{$tx->{messages}};
        my @row = ($tx->{time}, $tx->{id} || '', $tx->{client}, $tx->{host},
                   site_for_host($tx->{host}, $vhosts), $method, $uri, $tx->{status},
                   tx_blocked($tx) ? 'yes' : 'no', join(' ', @ids),
                   join(' | ', grep { $_ ne '' } map { $_->{msg} || '' } @m),
                   join(' | ', grep { $_ ne '' } map { $_->{data} || '' } @m));
        $out .= join(',', map { csv_field($_) } @row) . "\r\n";
    }
    return $out;
}

# Log files for a ZIP export: the current file and up to $history rotated
# copies (file.1, file.2.gz, ...). Returns list of [path, size].
sub log_files_with_rotated {
    my ($file, $history) = @_;
    my @f;
    push(@f, $file) if (-r $file);
    for (my $i = 1; $i <= $history && $i <= 7; $i++) {
        my ($r) = grep { -r $_ } ("$file.$i", "$file.$i.gz");
        push(@f, $r) if ($r);
    }
    return map { [$_, -s $_ || 0] } @f;
}

# File name part for downloads: host name and local time.
sub export_stamp {
    my $host = defined(&get_system_hostname) ? &get_system_hostname() : 'server';
    $host =~ s/[^A-Za-z0-9.-]+/-/g;
    return $host . "-" . POSIX::strftime("%Y%m%d-%H%M", localtime(time()));
}

# Write a ZIP of the log files @$files to $out (default STDOUT) as it reads
# them, so large logs never sit in memory. Files that are already gzip
# compressed are stored as they are. The last entry is manifest.txt:
# $note, then the size and SHA-256 of every file, so a copy handed on can be
# checked later. Returns '' or an error.
#
# Webmin runs CGI scripts inside miniserv, where STDOUT is a tied handle with
# no binmode, so the ZIP is built in a small in-memory buffer that is printed
# and emptied after every chunk, never written to STDOUT by IO::Compress.
sub stream_zip {
    my ($files, $note, $out) = @_;
    require IO::Compress::Zip;
    require Digest::SHA;
    $out ||= \*STDOUT;
    binmode($out) if (!tied(*$out));
    my $total = 0;
    $total += (-s $_ || 0) foreach (@$files);
    my %o = (Stream => 1, Zip64 => $total > 3_500_000_000 ? 1 : 0, BinModeIn => 1);
    my $zbuf = '';
    my $flush = sub {
        return if ($zbuf eq '');
        print $out $zbuf;
        $zbuf = '';
    };
    my ($z, %used, @manifest);
    my $add = sub {
        my ($name, %e) = @_;
        if (!$z) {
            $z = IO::Compress::Zip->new(\$zbuf, %o, Name => $name, %e);
            return $z ? '' : "Cannot start the ZIP file: $IO::Compress::Zip::ZipError";
        }
        my $ok = $z->newStream(%o, Name => $name, %e);
        $flush->();
        return $ok ? '' : "Cannot add $name: $IO::Compress::Zip::ZipError";
    };
    foreach my $f (@$files) {
        open(my $in, '<', $f) || next;
        binmode($in);
        # Two logs with the same name (unlikely) keep their parent folder.
        (my $name = $f) =~ s#^.*/##;
        if ($used{$name}++) {
            ($name = $f) =~ s#^/+##;
            $name =~ s#/#_#g;
        }
        my $err = $add->($name, Time => (stat($f))[9],
                         ($f =~ /\.gz$/ ? (Method => IO::Compress::Zip::ZIP_CM_STORE()) : ()));
        return $err if ($err);
        my $sha = Digest::SHA->new(256);
        my ($buf, $size) = ('', 0);
        while (my $n = read($in, $buf, 1 << 20)) {
            $z->print($buf);
            $flush->();
            $sha->add($buf);
            $size += $n;
        }
        close($in);
        push(@manifest, sprintf("%s  %12d  %s  (%s)", $sha->hexdigest, $size, $name, $f));
    }
    return 'None of the log files could be read' if (!$z);
    my $err = $add->('manifest.txt', Time => time());
    return $err if ($err);
    $z->print(($note || '') . "\nSHA-256                                                           Bytes  File\n" .
              join("\n", @manifest) . "\n");
    $z->close();
    $flush->();
    return '';
}

# ---------------------------------------------------------------------------
# HTML helpers and design system
# ---------------------------------------------------------------------------

# name, version, author and description from module.info.
sub module_meta {
    my $dir = $module_root_directory || '.';
    my %m;
    if (open(my $fh, '<', "$dir/module.info")) {
        while (my $l = <$fh>) {
            chomp($l);
            $m{$1} = $2 if ($l =~ /^([a-z_]+)=(.*)$/);
        }
        close($fh);
    }
    $m{version} ||= '0.0.0';
    $m{author} ||= 'Shaifful';
    return %m;
}

# Inline line icons (24px grid, stroke = currentColor).
my %ICONS = (
    shield   => '<path d="M12 3l8 3v6c0 5-3.4 8.3-8 9-4.6-.7-8-4-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/>',
    gauge    => '<path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4-5"/><path d="M4 19h16"/>',
    globe    => '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
    activity => '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    filter   => '<path d="M4 5h16l-6 7.5V19l-4-2v-4.5L4 5z"/>',
    list     => '<path d="M9 6h11M9 12h11M9 18h11"/><path d="M4.5 6h.01M4.5 12h.01M4.5 18h.01"/>',
    sliders  => '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    bell     => '<path d="M6 9a6 6 0 1 1 12 0c0 6 2.5 7.5 2.5 7.5h-17S6 15 6 9z"/><path d="M10 20a2 2 0 0 0 4 0"/>',
    file     => '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5z"/><path d="M14 3v5h5M9 13h6M9 17h4"/>',
    tool     => '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6z"/>',
    info     => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    refresh  => '<path d="M20 11a8 8 0 0 0-14.6-4.5L4 8"/><path d="M4 4v4h4"/><path d="M4 13a8 8 0 0 0 14.6 4.5L20 16"/><path d="M20 20v-4h-4"/>',
    check    => '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    alert    => '<path d="M12 4l9 16H3l9-16z"/><path d="M12 10v4M12 17h.01"/>',
    x        => '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    user     => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    tag      => '<path d="M3 12V4h8l10 10-8 8L3 12z"/><path d="M7.5 7.5h.01"/>',
    package  => '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9"/>',
    wand     => '<path d="M4 20L15 9"/><path d="M17 3v4M15 5h4M19 11v2M18 12h2M11 3v2M10 4h2"/>',
    arrow    => '<path d="M5 12h14M13 6l6 6-6 6"/>',
    cloud    => '<path d="M7 18.5h10.5a4 4 0 0 0 .4-7.98A6 6 0 0 0 6.3 9.1 4.7 4.7 0 0 0 7 18.5z"/>',
    bot      => '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 4v4M9 13h.01M15 13h.01M9.5 17h5"/>',
    ban      => '<circle cx="12" cy="12" r="9"/><path d="M5.7 5.7l12.6 12.6"/>',
);
sub icon {
    my ($name, $size) = @_;
    $size ||= 16;
    my $p = $ICONS{$name} || $ICONS{info};
    return "<svg class='msm-ico' viewBox='0 0 24 24' width='$size' height='$size' fill='none' stroke='currentColor' ".
           "stroke-width='1.9' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>$p</svg>";
}

# Shared styles. Colours are tokens with translucent neutrals, so pages read
# well in light and dark Webmin themes (Authentic, Gray, Legacy).
sub print_ui_css {
    return if ($main::msm_css_done++);
    print <<'CSS';
<style>
.msm{--accent:#2f6fed;--accent-2:#1d4ed8;--accent-soft:rgba(47,111,237,.12);--line:rgba(127,127,127,.2);--line-2:rgba(127,127,127,.36);--soft:rgba(127,127,127,.05);--soft-2:rgba(127,127,127,.1);--ok:#1f9d55;--warn:#d98a00;--bad:#d64545;--r:14px;--r-sm:9px;--shadow:0 1px 2px rgba(16,24,40,.04),0 2px 6px rgba(16,24,40,.05);--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;--s1:#2a78d6;--s2:#eb6834;--tip-bg:#1f1f1e;--tip-fg:#f4f4f2;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;font-size:14px;line-height:1.5;max-width:1240px;color:inherit;-webkit-font-smoothing:antialiased}
@media (prefers-color-scheme:dark){.msm{--s1:#3987e5;--s2:#d95926;--tip-bg:#f0efec;--tip-fg:#1a1a19;--shadow:none}}
.msm *,.msm *::before,.msm *::after{box-sizing:border-box}
.msm a{color:var(--accent)}
.msm code,.msm .msm-path{font-family:var(--mono);font-size:12.5px}
.msm code{color:inherit;background:var(--soft-2);padding:1px 6px;border-radius:5px;border:0}
.msm .msm-ico{flex:none;display:inline-block;vertical-align:-3px}
.msm-meta{font-size:12.5px;opacity:.68}
.msm-lead{margin:-6px 0 18px;opacity:.72;max-width:820px}
.msm-h{font-size:12px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;opacity:.62;margin:28px 0 10px}

/* app bar + navigation */
.msm-appbar{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px 16px;padding:14px 16px;margin:0 0 12px;border:1px solid var(--line);border-radius:var(--r);background:linear-gradient(120deg,var(--accent-soft),transparent 55%);box-shadow:var(--shadow)}
.msm-brand{display:flex;align-items:center;gap:12px;min-width:0;color:inherit!important;text-decoration:none!important}
.msm-logo{width:42px;height:42px;border-radius:12px;display:grid;place-items:center;color:#fff;background:linear-gradient(145deg,#4f8cff,#1d4ed8);box-shadow:0 6px 16px -4px rgba(37,99,235,.55),inset 0 1px 0 rgba(255,255,255,.25);flex:none}
.msm .msm-logo .msm-ico{display:block;vertical-align:0}
.msm-brand-name{display:block;font-weight:700;font-size:16px;letter-spacing:-.01em;line-height:1.25}
.msm-brand-sub{display:block;font-size:12px;opacity:.65}
.msm-ver{display:inline-block;font-size:11px;font-weight:600;padding:1px 8px;border-radius:999px;border:1px solid var(--line-2);margin-left:6px;vertical-align:1px;opacity:.85}
.msm-appbar-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.msm-appbar-actions form{margin:0;display:inline}
.msm-nav{display:flex;flex-wrap:wrap;gap:3px;margin:0 0 22px;padding:4px;border:1px solid var(--line);border-radius:12px;background:var(--soft)}
.msm-nav a{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border-radius:9px;color:inherit!important;text-decoration:none!important;font-size:13.5px;font-weight:500;opacity:.72;white-space:nowrap;transition:background .15s,opacity .15s,color .15s}
.msm-nav a:hover{opacity:1;background:var(--soft-2)}
.msm-nav a.msm-active{opacity:1;background:var(--accent);color:#fff!important;box-shadow:0 2px 6px -2px rgba(37,99,235,.6)}
@media (max-width:760px){.msm-nav{flex-wrap:nowrap;overflow-x:auto;scrollbar-width:none;-webkit-overflow-scrolling:touch;-webkit-mask-image:linear-gradient(90deg,#000 82%,transparent);mask-image:linear-gradient(90deg,#000 82%,transparent)}.msm-nav::-webkit-scrollbar{display:none}}

/* status */
.msm-dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:8px;flex:none;vertical-align:1px}
.msm-ok{background:var(--ok);box-shadow:0 0 0 3px rgba(31,157,85,.18)}
.msm-warn{background:var(--warn);box-shadow:0 0 0 3px rgba(217,138,0,.2)}
.msm-bad{background:var(--bad);box-shadow:0 0 0 3px rgba(214,69,69,.18)}
.msm-na{background:#9a9a9a;box-shadow:0 0 0 3px rgba(127,127,127,.15)}
.msm-pill{display:inline-flex;align-items:center;gap:0;padding:5px 12px;border-radius:999px;font-size:12.5px;font-weight:600;border:1px solid var(--line-2);color:inherit!important;text-decoration:none!important;white-space:nowrap}
.msm-pill-ok{background:rgba(31,157,85,.1);border-color:rgba(31,157,85,.35)}
.msm-pill-warn{background:rgba(217,138,0,.1);border-color:rgba(217,138,0,.4)}
.msm-pill-bad{background:rgba(214,69,69,.1);border-color:rgba(214,69,69,.4)}
.msm-badge{display:inline-block;font-size:11px;font-weight:600;padding:1px 7px;border-radius:6px;background:var(--soft-2);vertical-align:1px}

/* surfaces */
.msm-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(200px,100%),1fr));gap:12px;margin:0 0 20px}
.msm-card,.msm-panel,.msm-chart{border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);min-width:0}
.msm-card{padding:16px 18px}
.msm-card-label{font-size:11.5px;letter-spacing:.07em;text-transform:uppercase;opacity:.6;font-weight:600}
.msm-card-value{display:flex;align-items:center;font-size:22px;font-weight:700;margin-top:6px;line-height:1.2;letter-spacing:-.015em}
.msm-card-sub{font-size:12.5px;opacity:.65;margin-top:5px;overflow-wrap:break-word}
.msm-panel,.msm-chart{padding:18px 20px;margin:0 0 16px}
.msm-panel-head{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px 16px;margin:0 0 12px}
.msm-panel-title,.msm-chart-title{font-weight:650;font-size:15px;letter-spacing:-.005em}
.msm-panel-sub,.msm-chart-sub{font-size:12.5px;opacity:.65;margin:2px 0 12px}
.msm-panel-head .msm-panel-sub{margin-bottom:0}
.msm-grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(460px,100%),1fr));gap:0 16px}
.msm-grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(300px,100%),1fr));gap:14px}

/* buttons */
.msm-btn,.msm input[type=submit],.msm button{display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:34px;padding:6px 14px;border-radius:var(--r-sm);border:1px solid var(--line-2);background:transparent;color:inherit!important;font:inherit;font-size:13px;font-weight:600;line-height:1.2;cursor:pointer;text-decoration:none!important;white-space:nowrap;box-shadow:none;transition:background .15s,border-color .15s,box-shadow .15s,transform .05s}
.msm-btn:hover,.msm input[type=submit]:hover,.msm button:hover{background:var(--soft-2)}
.msm-btn:active,.msm button:active{transform:translateY(1px)}
.msm .msm-btn-primary{background:var(--accent);border-color:var(--accent);color:#fff!important;box-shadow:0 1px 2px rgba(29,78,216,.3),inset 0 1px 0 rgba(255,255,255,.15)}
.msm .msm-btn-primary:hover{background:var(--accent-2);border-color:var(--accent-2)}
.msm .msm-btn-danger{color:var(--bad)!important;border-color:rgba(214,69,69,.45)}
.msm .msm-btn-sm{min-height:28px;padding:4px 10px;font-size:12.5px}
.msm button:disabled,.msm input:disabled{opacity:.5;cursor:not-allowed}
.msm-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:16px}

/* forms */
.msm input[type=text],.msm input[type=password],.msm input[type=email],.msm input[type=number],.msm input:not([type]),.msm select,.msm textarea{min-height:34px;padding:6px 10px;border:1px solid var(--line-2);border-radius:var(--r-sm);background:transparent;color:inherit;font:inherit;font-size:13.5px;max-width:100%;box-shadow:none;transition:border-color .15s,box-shadow .15s}
.msm textarea{display:block;width:100%;padding:12px 14px;line-height:1.6}
.msm input:focus,.msm select:focus,.msm textarea:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.msm select option{color:#111;background:#fff}
.msm input[type=radio],.msm input[type=checkbox]{accent-color:var(--accent);width:15px;height:15px;margin:0 8px 0 0;vertical-align:-2px}
.msm label{cursor:pointer}
.msm-field{display:grid;grid-template-columns:minmax(0,250px) minmax(0,1fr);gap:6px 28px;padding:16px 0;border-top:1px solid var(--line)}
.msm-field:first-child{border-top:0;padding-top:4px}
.msm-field-label{font-weight:600;font-size:13.5px}
.msm-field-help{font-size:12.5px;opacity:.65;margin-top:5px}
.msm-inline{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px}
.msm-choices{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr));gap:10px}
.msm-choice{display:flex;gap:2px;align-items:flex-start;padding:12px 14px;border:1px solid var(--line-2);border-radius:11px;transition:border-color .15s,background .15s,box-shadow .15s}
.msm-choice:hover{background:var(--soft)}
.msm-choice:has(input:checked){border-color:var(--accent);background:var(--accent-soft);box-shadow:inset 0 0 0 1px var(--accent)}
.msm-choice input{margin-top:3px}
.msm-choice b{display:block;font-size:13.5px}
.msm-choice small{display:block;font-size:12.5px;opacity:.7;margin-top:2px;line-height:1.45}
.msm-code{font-family:var(--mono)!important;font-size:12.5px!important;line-height:1.6!important;tab-size:4;white-space:pre;overflow:auto;min-height:420px;resize:vertical}
.msm-segctl{display:inline-flex;flex-wrap:wrap;gap:3px;padding:3px;border-radius:11px;background:var(--soft-2);margin:0 0 14px}
.msm-segctl a{padding:6px 12px;border-radius:8px;font-size:13px;font-weight:500;color:inherit!important;text-decoration:none!important;opacity:.75}
.msm-segctl a:hover{opacity:1}
.msm-segctl a.msm-on{opacity:1;background:var(--accent);color:#fff!important}
@media (max-width:640px){.msm-field{grid-template-columns:1fr}}

/* callouts + results */
.msm-alerts{margin:0 0 18px}
.msm-alert{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:12px 14px;margin:0 0 8px;border-radius:11px;border:1px solid rgba(217,138,0,.35);background:rgba(217,138,0,.08)}
.msm-alert::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--warn);flex:none;box-shadow:0 0 0 3px rgba(217,138,0,.2)}
.msm-alert.msm-alert-bad{border-color:rgba(214,69,69,.35);background:rgba(214,69,69,.08)}
.msm-alert.msm-alert-bad::before{background:var(--bad);box-shadow:0 0 0 3px rgba(214,69,69,.18)}
.msm-alert.msm-alert-info{border-color:rgba(47,111,237,.3);background:rgba(47,111,237,.07)}
.msm-alert.msm-alert-info::before{background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.msm-alert.msm-alert-ok{border-color:rgba(31,157,85,.3);background:rgba(31,157,85,.08)}
.msm-alert.msm-alert-ok::before{background:var(--ok);box-shadow:0 0 0 3px rgba(31,157,85,.18)}
.msm-alert-text{flex:1 1 300px;min-width:0}
.msm-result{border:1px solid var(--line);border-radius:var(--r);margin:0 0 14px;overflow:hidden;box-shadow:var(--shadow)}
.msm-result-head{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px 10px;padding:10px 16px;background:var(--soft);font-weight:600;border-bottom:1px solid var(--line)}
.msm-result-code{font-weight:400;font-size:12px;opacity:.7}
.msm-result pre{margin:0;padding:12px 16px;max-height:420px;overflow:auto;white-space:pre-wrap;font-family:var(--mono);font-size:12.5px;background:transparent;border:0;color:inherit}
.msm pre{font-family:var(--mono);font-size:12.5px}

/* tables */
.msm-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);margin:0 0 14px}
table.msm-table{width:100%;border-collapse:collapse;margin:0}
.msm table.msm-table th,.msm table.msm-table>tbody>tr>th,.msm table.msm-table>thead>tr>th{text-align:left;font-size:11.5px;letter-spacing:.06em;text-transform:uppercase;opacity:.75;font-weight:650;padding:10px 14px!important;background:var(--soft);border-bottom:1px solid var(--line);white-space:nowrap}
.msm table.msm-table td,.msm table.msm-table>tbody>tr>td{padding:11px 14px!important;border-top:1px solid var(--line);vertical-align:top!important;overflow-wrap:break-word;word-break:normal}
.msm table.msm-table tr:first-child td,.msm table.msm-table>tbody>tr:first-child>td{border-top:0}
.msm table.msm-table tr:hover td,.msm table.msm-table>tbody>tr:hover>td{background:var(--soft)}
table.msm-table td .msm-path{overflow-wrap:anywhere}
table.msm-kv{width:100%;border-collapse:collapse}
.msm table.msm-kv td,.msm table.msm-kv>tbody>tr>td{padding:9px 10px!important;border-top:1px solid var(--line);vertical-align:top!important}
.msm table.msm-kv tr:first-child td,.msm table.msm-kv>tbody>tr:first-child>td{border-top:0}
.msm table.msm-kv td.msm-k{width:40%;opacity:.72}
.msm table.msm-kv td.msm-v{overflow-wrap:anywhere}
.msm-vrow{display:flex;align-items:baseline}
.msm-vrow .msm-dot{position:relative;top:-1px}

/* site list */
.msm-list{border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden;margin:0 0 16px}
.msm-site{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(0,1fr) minmax(0,1.15fr) auto;gap:10px 28px;align-items:center;padding:16px 20px;border-top:1px solid var(--line)}
.msm-site:first-child{border-top:0}
.msm-site:hover{background:var(--soft)}
.msm-site-name{display:flex;align-items:center;font-weight:650;font-size:14.5px;letter-spacing:-.005em;min-width:0}
.msm-site-name span:last-child{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msm-site-meta{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;margin:7px 0 0 16px}
.msm-site-chips{display:inline-flex;flex-wrap:wrap;gap:4px}
.msm-chip-sm{display:inline-block;font-size:11.5px;line-height:1.4;padding:1px 7px;border-radius:6px;background:var(--soft-2);white-space:nowrap}
.msm-chip-site{font-size:12.5px;padding:3px 9px}
.msm-site-ports{font-size:11.5px;opacity:.6;white-space:nowrap}
.msm-site-stat{min-width:0}
.msm-site-nums{font-size:13px;margin:0 0 7px;white-space:nowrap}
.msm-site-nums b{font-size:15px;font-weight:700}
.msm-sep{opacity:.4;margin:0 2px}
.msm-site-top{display:grid;gap:3px;font-size:12.5px;min-width:0}
.msm-site-top > div{display:flex;align-items:baseline;gap:8px;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.msm-site-k{display:inline-block;width:58px;flex:none;font-size:11px;letter-spacing:.05em;text-transform:uppercase;opacity:.55}
.msm-site-actions{display:flex;gap:6px;justify-content:flex-end}
.msm-quiet summary{font-weight:600}
@media (max-width:900px){.msm-site{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.msm-site-actions{justify-content:flex-start}}
@media (max-width:560px){.msm-site{grid-template-columns:1fr}.msm-site-meta{margin-left:0}}

/* tiles */
.msm-tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(240px,100%),1fr));gap:12px}
.msm-tile{display:flex;gap:12px;align-items:flex-start;border:1px solid var(--line);border-radius:var(--r);padding:14px 16px;color:inherit!important;text-decoration:none!important;box-shadow:var(--shadow);transition:border-color .15s,transform .15s,box-shadow .15s}
.msm-tile:hover{border-color:var(--accent);transform:translateY(-1px);box-shadow:0 6px 18px -8px rgba(37,99,235,.45)}
.msm .msm-tile-ico{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;opacity:1;font-size:0;line-height:0;margin:0;background:var(--accent-soft);color:var(--accent);flex:none}
.msm .msm-tile-ico .msm-ico{display:block;vertical-align:0;margin:0}
.msm-tile > span:not(.msm-tile-ico) > b{display:block;margin-bottom:2px;font-size:14px}
.msm-tile > span:not(.msm-tile-ico) > span{display:block;font-size:12.5px;opacity:.68;line-height:1.45}

/* filters + charts */
.msm-filters{display:flex;flex-wrap:wrap;align-items:center;gap:8px 12px;margin:0 0 14px}
.msm-filters label{display:inline-flex;align-items:center;gap:6px}
.msm-chip{display:inline-flex;align-items:center;gap:6px;padding:3px 6px 3px 11px;border-radius:999px;border:1px solid var(--accent);background:var(--accent-soft);font-size:12.5px}
.msm-chip a{color:inherit!important;text-decoration:none!important;opacity:.6;padding:0 4px;font-size:15px;line-height:1}
.msm-chip a:hover{opacity:1}
.msm-legend{display:flex;flex-wrap:wrap;gap:4px 16px;font-size:12.5px;margin:0 0 10px}
.msm-sw{display:inline-block;width:10px;height:10px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.msm-plot{position:relative;padding-left:34px}
.msm-ytick{position:absolute;left:0;width:28px;text-align:right;font-size:11px;opacity:.6;transform:translateY(-50%);font-variant-numeric:tabular-nums}
.msm-gridline{position:absolute;left:34px;right:0;border-top:1px dashed var(--line)}
.msm-cols{position:relative;display:flex;align-items:stretch;gap:2px;height:170px;border-bottom:1px solid var(--line-2)}
.msm-col{position:relative;flex:1 1 0;min-width:2px;display:flex;flex-direction:column;justify-content:flex-end;gap:2px;cursor:default;border-radius:4px 4px 0 0}
.msm-seg{width:100%;flex:none}
.msm-seg-top{border-radius:4px 4px 0 0}
.msm-col:hover{background:var(--soft-2)}
.msm-tip{display:none;position:absolute;bottom:calc(100% + 6px);left:50%;transform:translateX(-50%);background:var(--tip-bg);color:var(--tip-fg);font-size:12px;line-height:1.45;padding:7px 10px;border-radius:8px;white-space:nowrap;z-index:20;pointer-events:none;box-shadow:0 6px 18px rgba(0,0,0,.2)}
.msm-tip.msm-tip-l{left:0;transform:none}.msm-tip.msm-tip-r{left:auto;right:0;transform:none}
.msm-col:hover .msm-tip{display:block}
.msm-xlabels{display:flex;gap:2px;margin-top:6px;font-size:11px;height:14px}
.msm-xlabels span{flex:1 1 0;min-width:2px;position:relative;opacity:.6}
.msm-xlabels span i{position:absolute;left:50%;transform:translateX(-50%);font-style:normal;white-space:nowrap}
.msm-hbars{display:flex;flex-direction:column;gap:2px}
.msm-hbar{display:grid;grid-template-columns:minmax(0,42%) minmax(0,1fr) 44px;align-items:center;gap:10px;padding:6px 8px;border-radius:8px;color:inherit!important;text-decoration:none!important}
.msm-hbar:hover{background:var(--soft-2)}
.msm-hbar.msm-on{background:var(--accent-soft)}
.msm-hbar-label{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.msm-hbar-label small{opacity:.65}
.msm-hbar-track{display:flex;gap:2px;height:12px;align-items:stretch}
.msm-hbar-track span{display:block;min-width:2px}
.msm-hbar-track span:first-child{border-radius:3px 0 0 3px}
.msm-hbar-track span:last-child{border-radius:0 4px 4px 0}
.msm-hbar-track span:only-child{border-radius:3px 4px 4px 3px}
.msm-hbar-val{text-align:right;font-size:13px;font-variant-numeric:tabular-nums}
.msm-empty{opacity:.65;font-size:13px;padding:10px 0}

/* insights + events */
.msm-ins{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:6px 14px;padding:10px 0;border-top:1px solid var(--line)}
.msm-ins-main{flex:1 1 240px;min-width:0;font-size:13px}
.msm-ins-sub{font-size:12px;opacity:.72;margin-top:2px;overflow-wrap:anywhere}
.msm-ins-side{display:flex;align-items:center;gap:10px;font-size:12.5px;white-space:nowrap}
.msm-events{display:flex;flex-direction:column;border:1px solid var(--line);border-radius:var(--r);box-shadow:var(--shadow);overflow:hidden}
.msm-ev{display:grid;grid-template-columns:150px minmax(0,1fr);gap:4px 16px;padding:12px 16px;border-top:1px solid var(--line)}
.msm-ev:first-child{border-top:0}
.msm-ev:hover{background:var(--soft)}
.msm-ev-meta{display:flex;flex-direction:column;gap:3px;font-size:13px}
.msm-ev-res{display:flex;align-items:center;white-space:nowrap;font-weight:600}
.msm-ev-res .msm-meta{margin-left:6px}
.msm-ev-time{font-size:12px;opacity:.68;white-space:nowrap;font-variant-numeric:tabular-nums}
.msm-ev-body{min-width:0;display:flex;flex-direction:column;gap:5px}
.msm-ev-req{display:flex;gap:8px;align-items:baseline;min-width:0}
.msm-ev-req .msm-path{overflow-wrap:anywhere;min-width:0}
.msm-ev-method{font-size:10.5px;font-weight:700;letter-spacing:.04em;padding:2px 6px;border-radius:5px;background:var(--soft-2);flex:none}
.msm-ev-who{font-size:12.5px;opacity:.78;overflow-wrap:anywhere}
.msm-ev-rules{display:flex;flex-wrap:wrap;gap:6px}
.msm-rule{display:inline-block;max-width:100%;font-size:12.5px;line-height:1.4;padding:3px 9px;border-radius:7px;background:var(--soft-2);overflow-wrap:break-word}
.msm-rule-score{opacity:.6;background:transparent;border:1px dashed var(--line-2)}
.msm details summary{cursor:pointer;font-weight:600;padding:8px 0}
@media (max-width:640px){.msm-ev{grid-template-columns:1fr}.msm-ev-meta{flex-direction:row;justify-content:space-between}.msm table.msm-kv td.msm-k{width:45%}}

/* footer + about */
.msm-foot{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px 16px;margin:36px 0 4px;padding-top:14px;border-top:1px solid var(--line);font-size:12px;opacity:.7}
.msm-foot a{color:inherit!important}
.msm-hero{display:flex;align-items:center;gap:20px;flex-wrap:wrap;padding:28px;border:1px solid var(--line);border-radius:18px;background:radial-gradient(120% 140% at 0% 0%,var(--accent-soft),transparent 60%);box-shadow:var(--shadow);margin:0 0 18px}
.msm-hero .msm-logo{width:72px;height:72px;border-radius:20px}
.msm-hero h2{margin:0;font-size:26px;letter-spacing:-.02em;line-height:1.2}
.msm-hero p{margin:6px 0 0;opacity:.75;max-width:640px}
.msm-hero-meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.msm-feature{display:flex;gap:14px;align-items:flex-start}
.msm-feature > span:not(.msm-tile-ico),.msm-tile > span:not(.msm-tile-ico){min-width:0;padding-top:1px}
.msm-feature > span:not(.msm-tile-ico) > b{display:block;font-size:13.5px}
.msm-feature > span:not(.msm-tile-ico) > span{display:block;font-size:12.5px;opacity:.7;line-height:1.45}
.msm-timeline{list-style:none;margin:0;padding:0}
.msm-timeline li{position:relative;padding:0 0 16px 22px;border-left:2px solid var(--line);margin-left:5px}
.msm-timeline li:last-child{border-left-color:transparent;padding-bottom:0}
.msm-timeline li::before{content:"";position:absolute;left:-7px;top:3px;width:12px;height:12px;border-radius:50%;background:var(--accent);box-shadow:0 0 0 3px var(--accent-soft)}
.msm-timeline li > b{display:block}
.msm-timeline li > span{display:block;font-size:12.5px;opacity:.72}
</style>
CSS
}

# Opens the page container and prints the app bar and tab navigation.
# Every page calls this right after ui_print_header and print_page_end()
# before ui_print_footer.
sub print_nav {
    my ($active, $lead) = @_;
    print_ui_css();
    my %m = module_meta();
    my $mode = current_engine_mode();
    my %pill = (On => ['ok', 'Protected'], DetectionOnly => ['warn', 'Detection only'],
                Off => ['bad', 'Engine off'], Unknown => ['bad', 'Not configured']);
    my $p = $pill{$mode} || $pill{Unknown};
    print "<div class='msm msm-viz'>\n";
    print "<div class='msm-appbar'><a class='msm-brand' href='index.cgi'><span class='msm-logo'>", icon('shield', 22),
          "</span><span><span class='msm-brand-name'>ModSecurity Manager<span class='msm-ver'>v",
          &html_escape($m{version}), "</span></span><span class='msm-brand-sub'>Web application firewall for Apache</span></span></a>",
          "<div class='msm-appbar-actions'><a class='msm-pill msm-pill-$p->[0]' href='mode.cgi' title='SecRuleEngine $mode'>",
          status_dot($p->[0]), &html_escape($p->[1]), "</a>";
    if (can_edit()) {
        print "<form method='post' action='actions.cgi'>", &ui_hidden('action', 'reload'),
              "<button type='submit' class='msm-btn msm-btn-sm' title='Test the configuration, then reload Apache'>",
              icon('refresh', 14), "Test &amp; reload</button></form>";
    }
    print "</div></div>\n";
    my @tabs = (
        ['index.cgi',      'Status',      'gauge'],
        ['sites.cgi',      'Sites',       'globe'],
        ['logs.cgi',       'Logs',        'activity'],
        ['blocks.cgi',     'Blocked IPs', 'ban'],
        ['exclusions.cgi', 'Exclusions',  'filter'],
        ['rules.cgi',      'Rules',       'list'],
        ['mode.cgi',       'Protection',  'sliders'],
        ['alerts.cgi',     'Alerts',      'bell'],
        ['ai_bots.cgi',    'AI bots',     'bot'],
        ['cloudflare.cgi', 'Cloudflare',  'cloud'],
        ['config_editor.cgi', 'Config',   'file'],
        ['actions.cgi',    'Maintenance', 'tool'],
        ['about.cgi',      'About',       'info'],
    );
    print "<nav class='msm-nav' aria-label='ModSecurity Manager'>";
    foreach my $t (@tabs) {
        my $on = $t->[0] eq ($active || '');
        print "<a href='$t->[0]'", ($on ? " class='msm-active' aria-current='page'" : ""), ">",
              icon($t->[2]), &html_escape($t->[1]), "</a>";
    }
    print "</nav>\n";
    print "<p class='msm-lead'>$lead</p>\n" if ($lead);
}

# Closes the container opened by print_nav, with the module footer.
sub print_page_end {
    my %m = module_meta();
    print "<div class='msm-foot'><span>ModSecurity Manager v", &html_escape($m{version}),
          " &middot; Built by ", &html_escape($m{author}), "</span>",
          "<a href='about.cgi'>About</a></div>\n";
    print "</div>\n";
}

# Primary form button.
sub msm_submit {
    my ($label, $kind, $name, $value) = @_;
    my $cls = 'msm-btn' . ($kind && $kind eq 'primary' ? ' msm-btn-primary' : '') .
              ($kind && $kind eq 'danger' ? ' msm-btn-danger' : '');
    return "<button type='submit' class='$cls'" .
           (defined($name) ? " name='" . &html_escape($name) . "' value='" . &html_escape($value) . "'" : "") .
           ">" . &html_escape($label) . "</button>";
}

# Settings row: label (+ help) on the left, control on the right.
sub field_row {
    my ($label, $control, $help) = @_;
    return "<div class='msm-field'><div><div class='msm-field-label'>$label</div></div><div>$control" .
           ($help ? "<div class='msm-field-help'>$help</div>" : "") . "</div></div>\n";
}

sub callout {
    my ($kind, $html, $action) = @_;
    my $cls = $kind && $kind ne 'warn' ? " msm-alert-$kind" : '';
    return "<div class='msm-alert$cls'><div class='msm-alert-text'>$html</div>" . ($action || '') . "</div>\n";
}

# Shows an alert e-mail as the recipient sees it. The HTML is rendered in a
# sandboxed iframe (no scripts, no same-origin access).
sub print_email_preview {
    my ($subject, $text, $html) = @_;
    print "<div class='msm-panel'><div class='msm-panel-head'><div><div class='msm-panel-title'>E-mail preview</div>",
          "<div class='msm-panel-sub'>Subject: <b>", &html_escape($subject), "</b></div></div></div>\n";
    print "<iframe title='Alert e-mail preview' sandbox='' srcdoc='", &html_escape($html),
          "' style='width:100%;height:880px;border:1px solid var(--line);border-radius:10px;background:#f3f5f9'></iframe>\n";
    print "<details><summary>Plain-text version (also used for Telegram)</summary><pre style='white-space:pre-wrap'>",
          &html_escape($text), "</pre></details></div>\n";
}

# Log window selector: current log only, or include rotated copies.
sub history_select {
    my ($file, $history) = @_;
    my $avail = rotated_log_count($file);
    my $h = "<label>Window <select name='history'>";
    $h .= "<option value='0'" . (!$history ? " selected" : "") . ">Current log (last " . tail_line_limit() . " lines)</option>";
    foreach my $n (1, 2, 3, 5, 7) {
        next if ($n > $avail);
        $h .= "<option value='$n'" . ($history == $n ? " selected" : "") . ">+ $n rotated log" . ($n > 1 ? "s" : "") . "</option>";
    }
    return $h . "</select></label>";
}

sub print_history_form {
    my ($action, $file, $history) = @_;
    print "<form method='get' action='$action' class='msm-filters'>", history_select($file, $history),
          &ui_submit("Show"), "</form>\n";
}

# Coloured status dot: ok | warn | bad | na
sub status_dot {
    my ($state) = @_;
    $state = 'na' unless ($state && $state =~ /^(?:ok|warn|bad|na)$/);
    return "<span class='msm-dot msm-$state'></span>";
}

sub print_command_result {
    my ($title, $code, $out) = @_;
    print_ui_css();
    my $state = $code == 0 ? 'ok' : 'bad';
    print "<div class='msm-result'><div class='msm-result-head'><span>", status_dot($state),
          &html_escape($title), "</span><span class='msm-result-code'>",
          ($code == 0 ? "Succeeded" : "Failed"), " &middot; exit code ", &html_escape($code),
          "</span></div>";
    print "<pre>", &html_escape($out), "</pre>" if (defined($out) && $out =~ /\S/);
    print "</div>\n";
}

sub print_reload_form {
    return if (!can_edit());
    print "<form method='post' action='actions.cgi' class='msm-actions'>", &ui_hidden("action", "reload"),
          msm_submit("Reload Apache now", 'primary'), "</form>\n";
}

# Monospace editor; read-only for users without edit access.
sub text_editor {
    my ($name, $data, $rows) = @_;
    my $ro = can_edit() ? '' : ' readonly';
    return "<textarea class='msm-code' name='" . &html_escape($name) . "' rows='" . int($rows) .
           "' spellcheck='false' autocapitalize='off' autocomplete='off' wrap='off'$ro>" .
           &html_escape($data) . "</textarea>\n";
}

sub print_readonly_notice {
    print callout('info', "You have <b>read-only</b> access to this module. Ask a Webmin administrator to change settings.")
        if (!can_edit());
}

1;
