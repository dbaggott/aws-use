# aws-use

Switch AWS IAM Identity Center (SSO) accounts and roles fast — across **multiple
SSO sessions** (e.g. work and personal). `aws-use` discovers every account/role
you can assume, lets you pick one, manages the `~/.aws/config` profile for it,
and sets `AWS_PROFILE` in your current shell.

```
$ aws-use                       # pick interactively; sets AWS_PROFILE
* dnbg    dnbg-operations   224850139999   AdministratorAccess  (expires in 8h)

$ aws-use dnbg admin            # filter words jump straight to a match
* dnbg    dnbg-management   626716204703   AdministratorAccess  (expires in 8h)

$ aws-use ls                    # everything you can assume; * marks the active one
  SESSION   ACCOUNT           ACCOUNT ID     ROLE
  dnbg      dnbg-management    626716204703   AdministratorAccess
* dnbg      dnbg-operations   224850139999   AdministratorAccess  (expires in 8h)
  work      acme-prod         111111111111   ReadOnlyAccess

$ aws-use current               # the active profile, same row format
* dnbg    dnbg-operations   224850139999   AdministratorAccess  (expires in 8h)
```

It's a self-contained Go binary — no `aws` CLI or `jq` dependency. Discovery
calls `sso:ListAccounts` / `sso:ListAccountRoles` with your cached SSO token, so
you never pre-create profiles by hand. For the account/role you pick, `aws-use`
ensures an SSO-backed `[profile …]` block exists in `~/.aws/config` (so it
auto-refreshes and works with Terraform) and then sets `AWS_PROFILE`. It
*selects* the account/role — it doesn't assume the role or fetch credentials
itself; your AWS CLI, SDKs, and Terraform resolve those from the profile on
demand. Login uses
the authorization-code + PKCE flow (like `aws sso login`) and writes the **same**
`~/.aws/sso/cache` token the AWS CLI uses, so a session you log in here is reused
everywhere — and the refresh token means it renews silently until the session
lapses, rather than re-prompting the browser. (Set `AWS_USE_DEVICE_AUTH=1` for
the device-authorization flow instead, for headless/remote shells with no local
browser.)

Setting `AWS_PROFILE` in your shell is why the shell hook is required: only code
running *in* your shell can change its environment, so the hook `eval`s the
export `aws-use` prints (the same reason `aws sso login` alone can't switch you).

## Configuration

`aws-use` reads your existing `[sso-session …]` blocks from `~/.aws/config` —
multiple SSO orgs simply means multiple blocks, and `aws-use` spans them all. If
you have none yet, create one per portal with `aws configure sso` (name the
session, e.g. `dnbg`).

| Setting | Effect |
|---|---|
| `~/.aws/config` `[sso-session …]` blocks | The SSO sessions `aws-use` discovers and switches between |
| `AWS_USE_PROFILE_TEMPLATE` | Generated profile-name template. Default `{account}-{role}`; tokens: `{session}`, `{account}`, `{role}` |
| `AWS_USE_DEVICE_AUTH` | If set, log in with the device-authorization flow (open the URL on any device) instead of the default local-browser PKCE flow — for headless/remote shells |

## Install

Pick one. Homebrew installs the latest [release](https://github.com/dbaggott/aws-use/releases) (and shell completions); from source builds whatever you have checked out. **After installing, add the shell hook** (below) — the tool can't switch your shell without it.

### Homebrew (recommended on macOS)

```sh
brew tap dbaggott/tap
brew install aws-use
```

### go install

```sh
go install github.com/dbaggott/aws-use@latest
```

### From source

```sh
git clone https://github.com/dbaggott/aws-use.git
cd aws-use
make install                        # installs to ~/.local/bin
# or: make install PREFIX=/usr/local
```

### Shell hook (required)

Add to your `~/.zshrc` or `~/.bashrc`:

```sh
eval "$(aws-use shellenv)"
```

## Usage

```
aws-use [filter…]
```

Running `aws-use` with no arguments picks interactively (session → account →
role). Filter words narrow the list or jump straight to a match — they match
session, account, and role names, and `aws-use <TAB>` completes session names.

| Command | Effect |
|---|---|
| `aws-use [filter…]` | Pick an account/role (filtered by the words) and set `AWS_PROFILE` |
| `aws-use ls` | List every account/role you can assume; `*` marks the active one + its expiry |
| `aws-use current` | Show the active profile — account/role and token expiry |
| `aws-use login [session]` | Authenticate a session. Usually unnecessary: switching logs in automatically, and `ls` offers to log in when needed |
| `aws-use shellenv` | Print the shell hook (for your rc) |

If a session's token is missing or expired, the switch flow logs you in first
(browser device-authorization flow).

## Development

Build from the checkout and load the hook + completion into your current shell:

```sh
source dev.sh
```

Checks:

```sh
make test        # go test -race -cover
make lint        # golangci-lint + gofmt
make shellcheck  # lint the shellenv hook + test harness
make shelltest   # exercise the hook under bash 3.2 + zsh
```

## Releasing

Bump `VERSION` and merge to main. CI tags the commit `v<VERSION>`, publishes a
GitHub Release with cross-compiled binaries, and updates the Homebrew tap formula
— merging the bump is the whole release.

## Requirements

A configured AWS IAM Identity Center (SSO) session in `~/.aws/config`, and
`bash` 3.2+ or `zsh` for the shell hook (macOS ships both). No `aws` CLI or `jq`
required.

## License

MIT — see [LICENSE](LICENSE).
