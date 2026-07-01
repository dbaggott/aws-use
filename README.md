# aws-use

Switch AWS IAM Identity Center (SSO) accounts and roles fast. `aws-use`
discovers every account/role you can assume — across **multiple SSO sessions**
(e.g. work and personal) — lets you pick one, manages the `~/.aws/config`
profile for it, and sets `AWS_PROFILE` in your current shell.

```
$ aws-use
? SSO session: dnbg
? account / role: dnbg-management      AdministratorAccess
→ dnbg-management-AdministratorAccess (dnbg-management / AdministratorAccess)

$ aws-use dnbg ops admin        # fuzzy: jump straight to a match
→ dnbg-operations-AdministratorAccess (dnbg-operations / AdministratorAccess)
```

It's a self-contained Go binary — no `aws` CLI or `jq` dependency. Logins and
the token cache are written in the same format the AWS CLI and Terraform read,
so a session you log in here is reused everywhere (and vice versa).

## Install

**Homebrew:**
```bash
brew install dbaggott/tap/aws-use
```

**From source:**
```bash
go install github.com/dbaggott/aws-use@latest   # or: make install
```

Then add the shell hook to your `~/.zshrc` / `~/.bashrc` — required, because only
code running *in your shell* can change `AWS_PROFILE`:
```bash
eval "$(aws-use shellenv)"
```

## Setup

`aws-use` reads your existing `[sso-session …]` blocks from `~/.aws/config` —
nothing else to configure. If you don't have any yet, create one per SSO portal:
```bash
aws configure sso        # name the session, e.g. "dnbg"
```
Multiple SSO orgs = multiple `[sso-session …]` blocks. `aws-use` spans them all.

## Usage

| Command | What it does |
|---|---|
| `aws-use` | Pick session → account → role, set `AWS_PROFILE`. |
| `aws-use <query…>` | Same, but fuzzy-filtered (e.g. `aws-use dnbg admin`). A query word matching a session name selects it. |
| `aws-use ls` | List every account/role across logged-in sessions. |
| `aws-use login [session]` | Log in to a session (refresh its token). |
| `aws-use current` | Print the active `AWS_PROFILE`. |
| `aws-use shellenv` | Print the shell hook. |

If a session's token is missing or expired, the switch flow logs you in
automatically (browser device-authorization flow).

## How it works

- **Discovery:** calls `sso:ListAccounts` / `sso:ListAccountRoles` with your
  cached SSO token — no pre-created profiles needed.
- **Profiles:** for the account/role you pick, it ensures a `[profile …]` block
  exists in `~/.aws/config` (SSO-backed, so it auto-refreshes and works with
  Terraform), then exports `AWS_PROFILE`. Profile names follow
  `{account}-{role}` by default; override with `AWS_USE_PROFILE_TEMPLATE`
  (tokens: `{session}`, `{account}`, `{role}`).
- **Token cache:** login writes `~/.aws/sso/cache/<sha1(session)>.json` — the
  exact file the AWS CLI and SDKs use, so sessions are shared, not duplicated.

## Status

v0. The core (multi-session discovery, profile management, shell switching) is
in place. The device-authorization login does not yet refresh tokens silently
on expiry in every case — re-run `aws-use login <session>` if a token lapses.

## License

MIT
