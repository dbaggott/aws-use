// Package cli wires the command surface for aws-use.
package cli

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dbaggott/aws-use/internal/awsconfig"
	"github.com/dbaggott/aws-use/internal/sso"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

// Version is overridden at build time via -ldflags.
var Version = "dev"

// profileTemplate controls generated profile names. Tokens: {session},
// {account}, {role}. Overridable with AWS_USE_PROFILE_TEMPLATE.
const defaultProfileTemplate = "{account}-{role}"

func Execute() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "aws-use:", err)
		os.Exit(1)
	}
}

func newRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "aws-use [filter...]",
		Short: "Switch your shell's AWS account/role",
		Long: `Switch your shell's AWS account/role — across all your SSO sessions.

Run "aws-use" with no arguments to choose interactively: pick a session (if you
have more than one), then an account and role, and it sets AWS_PROFILE in your
current shell. Add filter words to narrow the list or jump straight to a match —
they match against session, account, and role names.

aws-use discovers everything you can assume (no pre-made profiles needed) and
writes the ~/.aws/config profile for you. It *selects* the account/role by
setting AWS_PROFILE to that SSO-backed profile — it does not assume the role or
fetch credentials itself; your AWS CLI, SDKs, and Terraform resolve those from
the profile on demand (signing you in automatically when the token has expired).

Requires the shell hook, added once to your ~/.zshrc or ~/.bashrc:
  eval "$(aws-use shellenv)"
Without it, aws-use prints the profile it picked but can't change your shell.`,
		Example: `  aws-use                 pick an account/role interactively, then switch
  aws-use prod            filter to matches of "prod"
  aws-use dnbg admin      jump to the dnbg session's admin role
  aws-use ls              list every account/role you can assume`,
		Version:           Version,
		SilenceUsage:      true,
		SilenceErrors:     true,
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: completeFilter,
		RunE:              func(cmd *cobra.Command, args []string) error { return runUse(cmd.Context(), args) },
	}

	// The `completion` command is auto-installed by the Homebrew formula and
	// never run by hand — hide it so it doesn't clutter help or tab-completion.
	root.CompletionOptions.HiddenDefaultCmd = true

	root.AddGroup(
		&cobra.Group{ID: "core", Title: "Commands:"},
		&cobra.Group{ID: "auth", Title: "Authentication:"},
	)

	root.AddCommand(
		// Internal: the shell hook invokes this as `aws-use use …`. Hidden — you
		// run bare `aws-use`, and the hook translates it.
		&cobra.Command{
			Use:    "use [query...]",
			Short:  "internal: switch flow used by the shell hook",
			Hidden: true,
			Args:   cobra.ArbitraryArgs,
			RunE:   func(cmd *cobra.Command, args []string) error { return runUse(cmd.Context(), args) },
		},
		&cobra.Command{
			Use:     "ls",
			Short:   "List every account/role you can assume",
			GroupID: "core",
			Args:    cobra.NoArgs,
			RunE:    func(cmd *cobra.Command, args []string) error { return runLs(cmd.Context()) },
		},
		&cobra.Command{
			Use:     "current",
			Short:   "Show the active AWS_PROFILE",
			GroupID: "core",
			Args:    cobra.NoArgs,
			RunE:    func(cmd *cobra.Command, args []string) error { return runCurrent(cmd.Context()) },
		},
		&cobra.Command{
			Use:   "login [session]",
			Short: "Authenticate an SSO session (usually automatic)",
			Long: `Refresh the browser sign-in for an SSO session.

You rarely need this: switching logs in automatically, and "ls" offers to log in
when needed. It's mainly for pre-authenticating or scripting.`,
			GroupID: "auth",
			Args:    cobra.MaximumNArgs(1),
			RunE:    func(cmd *cobra.Command, args []string) error { return runLogin(cmd.Context(), args) },
		},
		// Hidden from help/completion (still runnable): setup you do once, and the
		// hook is already documented in the long description, README, and caveats.
		&cobra.Command{
			Use:     "shellenv",
			Short:   "Print the shell hook to add to your shell rc",
			Hidden:  true,
			GroupID: "auth",
			Args:    cobra.NoArgs,
			RunE:    func(cmd *cobra.Command, args []string) error { fmt.Print(shellHook()); return nil },
		},
		// Hidden from help/completion (still runnable): the --version flag covers it.
		&cobra.Command{
			Use:    "version",
			Short:  "Print the aws-use version",
			Hidden: true,
			Args:   cobra.NoArgs,
			RunE:   func(cmd *cobra.Command, args []string) error { fmt.Println(Version); return nil },
		},
	)
	return root
}

// runUse resolves a session, ensures a token, discovers account/roles, narrows
// by the query, ensures a profile, and prints `export AWS_PROFILE=...` to stdout
// (everything else goes to stderr so the shell hook can eval stdout cleanly).
func runUse(ctx context.Context, query []string) error {
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return fmt.Errorf("no [sso-session] blocks in %s — run `aws configure sso` first", awsconfig.Path())
	}

	session, terms, err := resolveSession(sessions, query)
	if err != nil {
		return err
	}

	token, ok := sso.ValidToken(session.Name)
	if !ok {
		fmt.Fprintf(os.Stderr, "Logging in to %s…\n", session.Name)
		token, err = sso.Login(ctx, session.Name, session.StartURL, session.Region)
		if err != nil {
			return err
		}
	}

	var roles []sso.AccountRole
	if err := spin("discovering accounts in "+session.Name, func() error {
		var e error
		roles, e = sso.Discover(ctx, session.Name, session.Region, token)
		return e
	}); err != nil {
		return err
	}
	roles = filter(roles, terms)
	sortRoles(roles)
	switch len(roles) {
	case 0:
		return fmt.Errorf("no account/role in %s matches %q", session.Name, strings.Join(terms, " "))
	case 1:
		// unambiguous — fall through
	default:
		roles, err = pickRoles(roles)
		if err != nil {
			return err
		}
	}
	ar := roles[0]

	name := profileName(session, ar)
	if err := awsconfig.EnsureProfile(awsconfig.Profile{
		Name:       name,
		SSOSession: session.Name,
		AccountID:  ar.AccountID,
		RoleName:   ar.RoleName,
		Region:     session.Region,
	}); err != nil {
		return err
	}

	fmt.Fprint(os.Stderr, rowHeader())
	fmt.Fprint(os.Stderr, rowLine(true, session.Name, ar.AccountName, ar.AccountID, ar.RoleName))

	// The shell hook captures stdout via command substitution, so a piped stdout
	// means we're running under the hook: print only the export line for it to
	// eval. A terminal stdout means we were run directly — the export would have
	// no effect on the shell, so suppress that noise and guide the user to the
	// hook (which self-suppresses this branch once set up). The profile is
	// already written either way, so offer the manual export as a fallback.
	if isatty.IsTerminal(os.Stdout.Fd()) {
		fmt.Fprintln(os.Stderr, "aws-use: shell not switched — set up the shell hook once to enable switching:")
		fmt.Fprintln(os.Stderr, `  add to ~/.zshrc or ~/.bashrc:  eval "$(aws-use shellenv)"`)
		fmt.Fprintln(os.Stderr, "  then re-run: aws-use")
		fmt.Fprintf(os.Stderr, "  (or set it now: export AWS_PROFILE=%s)\n", name)
		return nil
	}
	fmt.Printf("export AWS_PROFILE=%s\n", name)
	return nil
}

func runLs(ctx context.Context) error {
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		return err
	}

	// Partition by whether we already have a usable token.
	var ready, missing []awsconfig.SSOSession
	for _, s := range sessions {
		if _, ok := sso.ValidToken(s.Name); ok {
			ready = append(ready, s)
		} else {
			missing = append(missing, s)
		}
	}

	// Offer to log in to the sessions we can't list yet — but only in a fully
	// interactive terminal (both stdin and stdout are TTYs). That way a piped or
	// redirected `ls` in either direction (`ls | grep`, `ls > file`, scripted)
	// never blocks on or is surprised by a prompt.
	if len(missing) > 0 && isatty.IsTerminal(os.Stdin.Fd()) && isatty.IsTerminal(os.Stdout.Fd()) {
		names := make([]string, len(missing))
		for i, s := range missing {
			names[i] = s.Name
		}
		chosen, err := pickMulti("Log in to these sessions? (space to select, enter to confirm)", names)
		if err != nil {
			return err
		}
		want := make(map[string]bool, len(chosen))
		for _, n := range chosen {
			want[n] = true
		}
		var still []awsconfig.SSOSession
		for _, s := range missing {
			if !want[s.Name] {
				still = append(still, s)
				continue
			}
			fmt.Fprintf(os.Stderr, "logging in to %s…\n", s.Name)
			if _, err := sso.Login(ctx, s.Name, s.StartURL, s.Region); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", s.Name, err)
				continue
			}
			ready = append(ready, s)
		}
		missing = still
	}

	// Note any sessions still not logged in (non-interactive, or declined).
	for _, s := range missing {
		fmt.Fprintf(os.Stderr, "%s: not logged in (run `aws-use login %s`)\n", s.Name, s.Name)
	}

	var rows []sso.AccountRole
	for _, s := range ready {
		token, ok := sso.ValidToken(s.Name)
		if !ok {
			continue
		}
		var ars []sso.AccountRole
		if err := spin("discovering "+s.Name, func() error {
			var e error
			ars, e = sso.Discover(ctx, s.Name, s.Region, token)
			return e
		}); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Name, err)
			continue
		}
		rows = append(rows, ars...)
	}
	sortRoles(rows)

	// Mark the row matching the active AWS_PROFILE (leading "*") and annotate it
	// with its session's token expiry.
	active := os.Getenv("AWS_PROFILE")
	if len(rows) > 0 {
		fmt.Print(rowHeader())
	}
	for _, r := range rows {
		isActive := active != "" && profileName(awsconfig.SSOSession{Name: r.Session}, r) == active
		fmt.Print(rowLine(isActive, r.Session, r.AccountName, r.AccountID, r.RoleName))
	}
	return nil
}

func runLogin(ctx context.Context, args []string) error {
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return fmt.Errorf("no [sso-session] blocks in %s", awsconfig.Path())
	}
	session, _, err := resolveSession(sessions, args)
	if err != nil {
		return err
	}
	if _, err := sso.Login(ctx, session.Name, session.StartURL, session.Region); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ logged in to %s\n", session.Name)
	return nil
}

func runCurrent(ctx context.Context) error {
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		fmt.Fprintln(os.Stderr, "AWS_PROFILE is not set")
		return nil
	}
	info, ok := awsconfig.ProfileInfo(profile)
	if !ok {
		fmt.Println(profile) // not an SSO profile we can describe
		return nil
	}

	// The account name only comes from a live ListAccounts call. Best-effort:
	// skip the network when the token isn't valid, so `current` still works
	// offline and reports expiry (the row shows "-" for the name then).
	account := ""
	if token, valid := sso.ValidToken(info.SSOSession); valid {
		_ = spin("checking "+info.SSOSession, func() error {
			name, err := sso.AccountName(ctx, info.Region, token, info.AccountID)
			account = name
			return err
		})
	}
	fmt.Print(rowHeader())
	fmt.Print(rowLine(true, info.SSOSession, account, info.AccountID, info.RoleName))
	return nil
}

// spin runs fn while animating a spinner on stderr, so a slow network doesn't
// look like a hang. It renders only when stderr is a terminal (piped/scripted
// output stays clean) and never touches stdout, which the shell hook captures.
func spin(title string, fn func() error) error {
	if !isatty.IsTerminal(os.Stderr.Fd()) {
		return fn()
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()

	frames := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for i := 0; ; i++ {
		select {
		case err := <-done:
			fmt.Fprint(os.Stderr, "\r\033[K") // clear the spinner line
			return err
		case <-ticker.C:
			fmt.Fprintf(os.Stderr, "\r%c %s", frames[i%len(frames)], title)
		}
	}
}

// rowFormat is the shared column layout used by `ls`, `current`, and the switch
// confirmation: marker, session, account, role, note.
const rowFormat = "%s %-10s  %-36s  %s%s\n"

// rowHeader is the column header printed above every row-format output.
func rowHeader() string {
	return fmt.Sprintf(rowFormat, " ", "SESSION", "ACCOUNT", "ROLE", "")
}

// accountCell combines the account name and id into one column — "name (id)", or
// just "id" when the name isn't known (e.g. offline `current`).
func accountCell(name, id string) string {
	if name == "" {
		return id
	}
	return name + " (" + id + ")"
}

// expiryNote renders the parenthetical token-status suffix for a session.
func expiryNote(session string) string {
	switch exp, present := sso.TokenExpiry(session); {
	case !present:
		return "  (not logged in)"
	case time.Now().After(exp):
		return "  (expired)"
	default:
		return "  (expires in " + humanDuration(time.Until(exp)) + ")"
	}
}

// rowLine renders one account/role line. The active row gets a "*" marker and an
// expiry note.
func rowLine(active bool, session, accountName, accountID, role string) string {
	marker, note := " ", ""
	if active {
		marker, note = "*", expiryNote(session)
	}
	return fmt.Sprintf(rowFormat, marker, session, accountCell(accountName, accountID), role, note)
}

// sortRoles orders account/roles by session, then account name, then role — the
// order used by `ls`, the interactive picker, and the switch flow.
func sortRoles(rs []sso.AccountRole) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Session != rs[j].Session {
			return rs[i].Session < rs[j].Session
		}
		if rs[i].AccountName != rs[j].AccountName {
			return rs[i].AccountName < rs[j].AccountName
		}
		return rs[i].RoleName < rs[j].RoleName
	})
}

// humanDuration renders a positive duration as e.g. "3h42m" or "42m" (or "<1m"),
// rounded to the minute.
func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	switch {
	case h > 0:
		return fmt.Sprintf("%dh%dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm", m)
	default:
		return "<1m"
	}
}

// completeFilter offers SSO session names as shell completions for the filter
// words. It reads only ~/.aws/config (no network), so completion stays instant;
// account/role names are left to the interactive picker.
//
// A switch targets exactly one session, so session names are only offered until
// one is chosen: with a single configured session there's nothing to pick, and
// once a prior word names a session the rest filter accounts/roles within it —
// suggesting another session name there would be nonsense (`aws-use dnbg qhcorp`).
func completeFilter(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	sessions, err := awsconfig.SSOSessions()
	if err != nil || len(sessions) <= 1 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	for _, a := range args {
		for _, s := range sessions {
			if strings.EqualFold(a, s.Name) {
				return nil, cobra.ShellCompDirectiveNoFileComp // a session is already chosen
			}
		}
	}
	var out []string
	for _, s := range sessions {
		if strings.HasPrefix(s.Name, toComplete) {
			out = append(out, s.Name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// resolveSession picks the target session: the only one, or one named by a query
// term, or an interactive choice. It returns the remaining (non-session) terms.
func resolveSession(sessions []awsconfig.SSOSession, query []string) (awsconfig.SSOSession, []string, error) {
	if len(sessions) == 1 {
		return sessions[0], query, nil
	}
	for i, term := range query {
		for _, s := range sessions {
			if strings.EqualFold(s.Name, term) {
				return s, append(append([]string{}, query[:i]...), query[i+1:]...), nil
			}
		}
	}
	names := make([]string, len(sessions))
	for i, s := range sessions {
		names[i] = s.Name
	}
	choice, err := pickOne("SSO session", names)
	if err != nil {
		return awsconfig.SSOSession{}, nil, err
	}
	for _, s := range sessions {
		if s.Name == choice {
			return s, query, nil
		}
	}
	return awsconfig.SSOSession{}, nil, fmt.Errorf("session %q not found", choice)
}

func filter(roles []sso.AccountRole, terms []string) []sso.AccountRole {
	if len(terms) == 0 {
		return roles
	}
	var out []sso.AccountRole
	for _, r := range roles {
		hay := strings.ToLower(r.AccountName + " " + r.AccountID + " " + r.RoleName)
		match := true
		for _, t := range terms {
			if !strings.Contains(hay, strings.ToLower(t)) {
				match = false
				break
			}
		}
		if match {
			out = append(out, r)
		}
	}
	return out
}

var slugRe = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func slug(s string) string {
	return strings.Trim(slugRe.ReplaceAllString(s, "-"), "-")
}

func profileName(s awsconfig.SSOSession, ar sso.AccountRole) string {
	tmpl := os.Getenv("AWS_USE_PROFILE_TEMPLATE")
	if tmpl == "" {
		tmpl = defaultProfileTemplate
	}
	r := strings.NewReplacer(
		"{session}", s.Name,
		"{account}", ar.AccountName,
		"{role}", ar.RoleName,
	)
	// Slug the whole assembled name, not just the substituted tokens, so a
	// custom template's own characters can't carry shell metacharacters into
	// the `export AWS_PROFILE=…` line the shell hook evals.
	return slug(r.Replace(tmpl))
}
