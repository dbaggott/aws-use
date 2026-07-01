// Package cli wires the command surface for aws-use.
package cli

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

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
		Use:   "aws-use [query...]",
		Short: "Switch AWS SSO accounts/roles fast",
		Long: `Switch your shell's AWS account/role across your SSO sessions.

Run "aws-use" (through the shell hook) to pick an account/role and set
AWS_PROFILE; add a query to filter, e.g. "aws-use dnbg admin". It discovers
everything you can assume, manages the ~/.aws/config profile, and logs you in
automatically when a session's token has expired.

One-time setup: add the shell hook to your shell rc — eval "$(aws-use shellenv)".`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE:          func(cmd *cobra.Command, args []string) error { return runUse(cmd.Context(), args) },
	}

	root.AddGroup(
		&cobra.Group{ID: "core", Title: "Commands:"},
		&cobra.Group{ID: "setup", Title: "Setup & auth:"},
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
			RunE:    func(cmd *cobra.Command, args []string) error { return runCurrent() },
		},
		&cobra.Command{
			Use:   "login [session]",
			Short: "Authenticate an SSO session (usually automatic)",
			Long: `Refresh the browser sign-in for an SSO session.

You rarely need this: switching logs in automatically, and "ls" offers to log in
when needed. It's mainly for pre-authenticating or scripting.`,
			GroupID: "setup",
			Args:    cobra.MaximumNArgs(1),
			RunE:    func(cmd *cobra.Command, args []string) error { return runLogin(cmd.Context(), args) },
		},
		&cobra.Command{
			Use:     "shellenv",
			Short:   "Print the shell hook to add to your shell rc",
			GroupID: "setup",
			Args:    cobra.NoArgs,
			RunE:    func(cmd *cobra.Command, args []string) error { fmt.Print(shellHook()); return nil },
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print the aws-use version",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, args []string) error { fmt.Println(Version); return nil },
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

	roles, err := sso.Discover(ctx, session.Name, session.Region, token)
	if err != nil {
		return err
	}
	roles = filter(roles, terms)
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

	fmt.Fprintf(os.Stderr, "→ %s (%s / %s)\n", name, ar.AccountName, ar.RoleName)

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

	// Offer to log in to the sessions we can't list yet — but only when stdin is
	// a terminal, so a piped/scripted `ls` never blocks on a prompt.
	if len(missing) > 0 && isatty.IsTerminal(os.Stdin.Fd()) {
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
		ars, err := sso.Discover(ctx, s.Name, s.Region, token)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", s.Name, err)
			continue
		}
		rows = append(rows, ars...)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Session != rows[j].Session {
			return rows[i].Session < rows[j].Session
		}
		if rows[i].AccountName != rows[j].AccountName {
			return rows[i].AccountName < rows[j].AccountName
		}
		return rows[i].RoleName < rows[j].RoleName
	})

	const format = "%-10s  %-24s  %-14s  %s\n"
	if len(rows) > 0 {
		fmt.Printf(format, "SESSION", "ACCOUNT", "ACCOUNT ID", "ROLE")
	}
	for _, r := range rows {
		fmt.Printf(format, r.Session, r.AccountName, r.AccountID, r.RoleName)
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

func runCurrent() error {
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		fmt.Println(p)
		return nil
	}
	fmt.Fprintln(os.Stderr, "AWS_PROFILE is not set")
	return nil
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
