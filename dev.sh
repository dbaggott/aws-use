# Build aws-use from this worktree and load its shell hook + completion into the
# CURRENT shell. Source it (do not execute):
#
#   source dev.sh
#
# Effects last only in this shell; open a new terminal to return to the
# installed aws-use.
# shellcheck shell=bash disable=SC1090
if make build; then
  eval "$(./aws-use shellenv)"
  case "${ZSH_VERSION:+zsh}${BASH_VERSION:+bash}" in
    *zsh*) source <(./aws-use completion zsh) ;;
    *bash*) source <(./aws-use completion bash) ;;
  esac
  echo "aws-use (dev) loaded from $PWD — open a new shell to revert"
fi
