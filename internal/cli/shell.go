package cli

// shellHook is printed by `aws-use shellenv`. It defines an `aws-use` shell
// function that wraps the binary: read-only subcommands pass straight through,
// while the switch path is run as `aws-use use …` and its `export AWS_PROFILE=…`
// output is eval'd into the current shell — the only way a child process can
// change the parent shell's environment.
const shellHook = `# aws-use shell hook. Add to your ~/.zshrc or ~/.bashrc:
#   eval "$(aws-use shellenv)"
aws-use() {
  case "${1:-}" in
    ls|login|current|shellenv|version|completion|help|-h|--help|--version)
      command aws-use "$@"
      ;;
    *)
      local _out
      _out="$(command aws-use use "$@")" || return $?
      [ -n "$_out" ] && eval "$_out"
      ;;
  esac
}
`
