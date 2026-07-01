package cli

import (
	"fmt"
	"os"

	"github.com/charmbracelet/huh"
	"github.com/dbaggott/aws-use/internal/sso"
)

// pickOne shows a single-select over options. The form renders to stderr so the
// shell hook can capture a clean `export` line on stdout.
func pickOne(title string, options []string) (string, error) {
	var choice string
	opts := make([]huh.Option[string], len(options))
	for i, o := range options {
		opts[i] = huh.NewOption(o, o)
	}
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().Title(title).Options(opts...).Value(&choice),
		),
	).WithOutput(os.Stderr).Run()
	return choice, err
}

// pickMulti shows a multi-select over options and returns the chosen ones.
func pickMulti(title string, options []string) ([]string, error) {
	var chosen []string
	opts := make([]huh.Option[string], len(options))
	for i, o := range options {
		opts[i] = huh.NewOption(o, o)
	}
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewMultiSelect[string]().Title(title).Options(opts...).Value(&chosen),
		),
	).WithOutput(os.Stderr).Run()
	return chosen, err
}

// pickRoles shows a single-select over account/role pairs and returns the chosen
// one (as a one-element slice, so callers can treat picked and unambiguous cases
// the same).
func pickRoles(roles []sso.AccountRole) ([]sso.AccountRole, error) {
	var idx int
	opts := make([]huh.Option[int], len(roles))
	for i, r := range roles {
		opts[i] = huh.NewOption(fmt.Sprintf("%-24s %s", r.AccountName, r.RoleName), i)
	}
	err := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[int]().Title("account / role").Options(opts...).Value(&idx),
		),
	).WithOutput(os.Stderr).Run()
	if err != nil {
		return nil, err
	}
	return []sso.AccountRole{roles[idx]}, nil
}
