package cli

import (
	"fmt"
	"os"
)

// shellHookFmt is the shell function printed by `aws-use shellenv`. `%[1]s` is
// replaced with the absolute path to this binary (via os.Executable), so the
// wrapper works even when the binary isn't on PATH — e.g. running it straight
// out of a build directory. Read-only subcommands pass straight through, while
// the switch path is run as `<bin> use …` and its `export AWS_PROFILE=…` output
// is eval'd into the current shell — the only way a child process can change
// the parent shell's environment.
const shellHookFmt = `# aws-use shell hook. Add to your ~/.zshrc or ~/.bashrc:
#   eval "$(aws-use shellenv)"
aws-use() {
  case "${1:-}" in
    ls|login|current|shellenv|version|completion|help|-h|--help|--version)
      command "%[1]s" "$@"
      ;;
    *)
      # Accept an explicit leading "use" too, so "aws-use use dnbg" does not
      # become "aws-use use use dnbg".
      [ "${1:-}" = "use" ] && shift
      local _out
      _out="$(command "%[1]s" use "$@")" || return $?
      [ -n "$_out" ] && eval "$_out"
      ;;
  esac
}
`

// shellHook returns the hook with this binary's absolute path substituted in.
func shellHook() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		exe = "aws-use"
	}
	return fmt.Sprintf(shellHookFmt, exe)
}
