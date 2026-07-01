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
		Use:           "aws-use [query...]",
		Short:         "Switch AWS SSO accounts/roles fast",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.ArbitraryArgs,
		RunE:          func(cmd *cobra.Command, args []string) error { return runUse(cmd.Context(), args) },
	}
	root.AddCommand(
		&cobra.Command{
			Use:   "use [query...]",
			Short: "Pick an account/role and print the AWS_PROFILE export (used by the shell hook)",
			Args:  cobra.ArbitraryArgs,
			RunE:  func(cmd *cobra.Command, args []string) error { return runUse(cmd.Context(), args) },
		},
		&cobra.Command{
			Use:   "ls",
			Short: "List every account/role across logged-in SSO sessions",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, args []string) error { return runLs(cmd.Context()) },
		},
		&cobra.Command{
			Use:   "login [session]",
			Short: "Log in to an SSO session (refresh its token)",
			Args:  cobra.MaximumNArgs(1),
			RunE:  func(cmd *cobra.Command, args []string) error { return runLogin(cmd.Context(), args) },
		},
		&cobra.Command{
			Use:   "current",
			Short: "Show the active AWS_PROFILE",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, args []string) error { return runCurrent() },
		},
		&cobra.Command{
			Use:   "shellenv",
			Short: "Print the shell hook to eval from your shell rc",
			Args:  cobra.NoArgs,
			RunE:  func(cmd *cobra.Command, args []string) error { fmt.Print(shellHook); return nil },
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
	fmt.Printf("export AWS_PROFILE=%s\n", name)
	return nil
}

func runLs(ctx context.Context) error {
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		return err
	}
	var rows []sso.AccountRole
	for _, s := range sessions {
		token, ok := sso.ValidToken(s.Name)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s: not logged in (run `aws-use login %s`)\n", s.Name, s.Name)
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
	for _, r := range rows {
		fmt.Printf("%-10s  %-22s  %-14s  %s\n", r.Session, r.AccountName, r.AccountID, r.RoleName)
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
	_, err = sso.Login(ctx, session.Name, session.StartURL, session.Region)
	return err
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
		"{session}", slug(s.Name),
		"{account}", slug(ar.AccountName),
		"{role}", slug(ar.RoleName),
	)
	return r.Replace(tmpl)
}
