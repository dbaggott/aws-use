# aws-use

Switch AWS IAM Identity Center (SSO) accounts and roles fast — across **multiple
SSO sessions** (e.g. work and personal). `aws-use` discovers every account/role
you can assume, lets you pick one, manages the `~/.aws/config` profile for it,
and sets `AWS_PROFILE` in your current shell.

```
$ aws-use
? SSO session: dnbg
? account / role: dnbg-management      AdministratorAccess
→ dnbg-management-AdministratorAccess (dnbg-management / AdministratorAccess)

$ aws-use dnbg ops admin        # fuzzy: jump straight to a match
→ dnbg-operations-AdministratorAccess (dnbg-operations / AdministratorAccess)

$ aws-use ls                    # everything you can assume, across sessions
dnbg      dnbg-management       626716204703    AdministratorAccess
dnbg      dnbg-operations       224850139999    AdministratorAccess
work      acme-prod             111111111111    ReadOnlyAccess
```

It's a self-contained Go binary — no `aws` CLI or `jq` dependency. Discovery
calls `sso:ListAccounts` / `sso:ListAccountRoles` with your cached SSO token, so
you never pre-create profiles by hand. For the account/role you pick, `aws-use`
ensures an SSO-backed `[profile …]` block exists in `~/.aws/config` (so it
auto-refreshes and works with Terraform) and then sets `AWS_PROFILE`. Login uses
the device-authorization flow and writes the **same** `~/.aws/sso/cache` token
the AWS CLI uses, so a session you log in here is reused everywhere — and vice
versa.

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

## Install

Pick one. Homebrew installs the latest [release](https://github.com/dbaggott/aws-use/releases); from source builds whatever you have checked out. **After installing, add the shell hook** (below) — the tool can't switch your shell without it.

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
aws-use [query…]
```

| Command | Effect |
|---|---|
| `aws-use` | Pick session → account → role, then set `AWS_PROFILE` |
| `aws-use <query…>` | Same, fuzzy-filtered (`aws-use dnbg admin`); a word matching a session name selects it |
| `aws-use ls` | List every account/role across logged-in sessions |
| `aws-use login [session]` | Log in to a session (refresh its token) |
| `aws-use current` | Print the active `AWS_PROFILE` |
| `aws-use shellenv` | Print the shell hook |
| `aws-use version` | Print the version |

If a session's token is missing or expired, the switch flow logs you in first
(browser device-authorization flow).

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
