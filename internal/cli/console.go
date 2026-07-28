package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/dbaggott/aws-use/internal/awsconfig"
	"github.com/dbaggott/aws-use/internal/browser"
	"github.com/dbaggott/aws-use/internal/console"
	"github.com/dbaggott/aws-use/internal/sso"
	"github.com/spf13/cobra"
)

// consoleOpts are the flags of the `console` command.
type consoleOpts struct {
	destination string
	region      string
	printOnly   bool
}

func newConsoleCmd() *cobra.Command {
	var opts consoleOpts
	cmd := &cobra.Command{
		Use:     "console [filter...]",
		Aliases: []string{"open"},
		Short:   "Open the AWS console for an account/role in your browser",
		Long: `Open the AWS Management Console, signed in as an account/role.

With no filter words this opens the console for your active AWS_PROFILE. That
path needs no network and no valid SSO token — the link is built from
~/.aws/config alone, and the browser signs in with its own access portal
session. Filter words select a different account/role exactly as switching does
(session, account, and role names), and never change your shell.

Not every role can necessarily be used in the console, and Identity Center does
not publish which ones can: the account/role list aws-use discovers carries no
console-access flag. So a role that can't be used there fails at the portal
after you land, not here. The link is always printed before the browser opens,
so you can see precisely what was attempted.`,
		Example: `  aws-use console               open the console for the account/role you're on
  aws-use console prod          open the console for the "prod" account instead
  aws-use console --region us-west-2
  aws-use console -d https://console.aws.amazon.com/s3/home
  aws-use console --print       print the link instead of opening it`,
		GroupID:           "core",
		Args:              cobra.ArbitraryArgs,
		ValidArgsFunction: completeFilter,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runConsole(cmd.Context(), args, opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.destination, "destination", "d", "",
		"Console URL to land on (default: the permission set's relay state, else console home)")
	f.StringVarP(&opts.region, "region", "r", "", "Land on the console home of this region")
	f.BoolVarP(&opts.printOnly, "print", "p", false, "Print the link on stdout instead of opening a browser")
	cmd.MarkFlagsMutuallyExclusive("destination", "region")
	return cmd
}

// runConsole resolves an account/role and opens (or prints) the access portal
// link that signs in to the AWS console as it. It never touches AWS_PROFILE —
// opening the console for one account while your shell points at another is a
// normal thing to want.
func runConsole(ctx context.Context, query []string, opts consoleOpts) error {
	sessions, err := awsconfig.SSOSessions()
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		return fmt.Errorf("no [sso-session] blocks in %s — run `aws configure sso` first", awsconfig.Path())
	}

	session, ar, err := consoleTarget(ctx, sessions, query)
	if err != nil {
		return err
	}

	destination := opts.destination
	if destination == "" && opts.region != "" {
		destination, err = console.RegionHome(opts.region)
		if err != nil {
			return err
		}
	}
	link, err := console.URL(session.StartURL, ar.AccountID, ar.RoleName, destination)
	if err != nil {
		return fmt.Errorf("cannot build a console link for session %q: %w", session.Name, err)
	}

	if opts.printOnly {
		fmt.Println(link)
		return nil
	}

	// No active marker or expiry note here, unlike `ls`/`current`: the console
	// signs in through the browser's own portal session, so the CLI token's
	// expiry says nothing about whether this link will work.
	fmt.Fprint(os.Stderr, rowHeader())
	fmt.Fprint(os.Stderr, rowLine(false, session.Name, ar.AccountName, ar.AccountID, ar.RoleName))
	fmt.Fprintf(os.Stderr, "opening %s\n", link)
	if err := browser.Open(link); err != nil {
		return fmt.Errorf("opening a browser: %w — open the URL above by hand, or re-run with --print", err)
	}
	return nil
}

// consoleTarget picks the account/role to open. With no filter words it uses the
// active AWS_PROFILE, which needs no token and no network; anything else (no
// profile set, a non-SSO profile, filter words given) falls through to the same
// discover-and-pick flow the switch uses.
func consoleTarget(ctx context.Context, sessions []awsconfig.SSOSession, query []string) (awsconfig.SSOSession, sso.AccountRole, error) {
	if len(query) == 0 {
		session, ar, why := activeTarget(sessions)
		if why == "" {
			return session, ar, nil
		}
		// Say why we're falling back rather than silently opening a picker: from
		// the outside "aws-use console" not using AWS_PROFILE looks like a bug.
		fmt.Fprintf(os.Stderr, "aws-use: %s — pick an account/role instead\n", why)
	}
	return resolveRole(ctx, sessions, query)
}

// activeTarget resolves AWS_PROFILE to a session and account/role. The third
// return is empty on success, and otherwise explains why the active profile
// can't be used — an explanation, not an error, because every reason is a cue to
// fall back to picking rather than to give up.
//
// The account name is left blank: naming it costs a live sso:ListAccounts call,
// and the row format already renders a nameless account as its bare id.
func activeTarget(sessions []awsconfig.SSOSession) (awsconfig.SSOSession, sso.AccountRole, string) {
	profile := os.Getenv("AWS_PROFILE")
	if profile == "" {
		return awsconfig.SSOSession{}, sso.AccountRole{}, "AWS_PROFILE is not set"
	}
	info, ok := awsconfig.ProfileInfo(profile)
	if !ok {
		return awsconfig.SSOSession{}, sso.AccountRole{},
			fmt.Sprintf("AWS_PROFILE=%s is not an SSO-backed profile", profile)
	}
	// ProfileInfo only promises an sso_session; the account and role keys can be
	// missing from a hand-edited profile. Treat that as one more cue to pick,
	// rather than letting the empty fields fail deeper down where the message
	// would name the session instead of the malformed profile.
	if info.AccountID == "" || info.RoleName == "" {
		return awsconfig.SSOSession{}, sso.AccountRole{},
			fmt.Sprintf("AWS_PROFILE=%s has no sso_account_id/sso_role_name", profile)
	}
	for _, s := range sessions {
		if s.Name == info.SSOSession {
			return s, sso.AccountRole{
				Session:   s.Name,
				AccountID: info.AccountID,
				RoleName:  info.RoleName,
			}, ""
		}
	}
	return awsconfig.SSOSession{}, sso.AccountRole{},
		fmt.Sprintf("AWS_PROFILE=%s uses sso-session %q, which is not in %s",
			profile, info.SSOSession, awsconfig.Path())
}
