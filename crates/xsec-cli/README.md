# xsec-cli

`xsec-cli` encrypts each value in a dotenv document with the `xsec` library and
injects decrypted values into child processes without creating a plaintext
temporary file.

The Cargo package is named `xsec-cli`; the installed executable is `xsec`.

## File layout

```text
.env                plaintext input; do not commit
.xsec               encrypted default environment
.xsec.production    encrypted production environment
.xsec.keys          protected data-encryption-key storage; do not commit
```

The `.xsec` file remains a dotenv document: variable names, comments, ordering,
and blank lines stay readable, while protected values use the
`xsec:<base64url-no-padding>` format. The `xsec:` prefix is reserved for
protected values. The `.xsec.keys` storage file contains the wrapped data
encryption key and protector metadata. Losing `.xsec.keys` makes the encrypted
values unrecoverable. Back it up and provision it through an appropriate
secret-management channel.

## Usage

Initialize password-protected storage:

```text
xsec init
```

The password is read from the terminal without echoing. For non-interactive
use, pass it through standard input:

```text
printf '%s' "$XSEC_PASSWORD" | xsec init --password
```

Use `--storage <path>` on commands that access the protected key storage. Its
default path is `.xsec.keys`.

Encrypt and run:

```text
xsec encrypt -i .env -o .xsec
xsec run -f .xsec -- your-command
```

Decrypt to standard output or an explicit file:

```text
xsec decrypt -i .xsec --stdout
xsec decrypt -i .xsec -o .env
```

`--stdout` is implicit when `--output` is omitted.

Read, update, or remove one value:

```text
xsec get API_TOKEN -f .xsec
xsec set API_TOKEN -f .xsec
xsec set API_TOKEN "$API_TOKEN" -f .xsec
xsec del API_TOKEN -f .xsec
```

`set` prompts without echo when the value is omitted. A positional value is
visible to shell history and may be visible to process inspection tools. A
value may be empty, but cannot contain NUL or carriage-return bytes. If the
environment file does not exist, `set` creates it. `get` writes only the value,
without a label or added newline. `get` and `del` exit with status 1 when the
key is absent.

Initialization always creates password-protected storage. On a supported
platform, add system protection afterward with a stable logical identity:

```text
xsec protector add system --identity your-project-id
xsec run --protector system -- your-command
```

Adding the protector first unlocks the existing storage with its password and
then wraps the same data-encryption key with system protection. Pass
`--password` to read that password from standard input. The identity is
required only when adding the system protector. Later commands restore its
hash from the protected key storage. Do not derive the identity from an
absolute path; moving the project must not change it.

List the configured protectors without unlocking the storage:

```text
xsec protector list
```

Remove a protector after authorizing with another configured protector:

```text
xsec protector remove system
xsec protector remove password
```

The CLI automatically uses the other configured protector. Use
`--unlock-with <password|system>` to select one explicitly when needed, and
`--password` when the selected password protector must read from standard
input. The last protector cannot be removed.

On macOS, the executable must be signed with a provisioning profile that
authorizes its `com.apple.application-identifier` entitlement. An ad-hoc signed
binary produced by `cargo run` cannot use this Secure Enclave protector.

## Runtime behavior
- Existing process environment variables take precedence by default.
- `--override` lets values from the encrypted file replace existing values.
- Duplicate variable names and malformed dotenv input are rejected.
- Missing storage, failed authentication, and unsupported system protection
  are fatal. The CLI never falls back to a plaintext `.env` file.
- `run`, `get`, and `decrypt` preserve plaintext values and decrypt values with
  the `xsec:` prefix. A malformed value using this reserved prefix is rejected.
  Only encrypted values receive confidentiality and integrity protection.
- Output files are written atomically. New files use owner-only permissions on
  Unix platforms.
- Passwords, plaintext values, and ciphertext are not written to diagnostics.
- Every encrypted value uses a fresh nonce and is authenticated against its
  variable name. Moving ciphertext to another key causes decryption to fail.
- `set` replaces only the selected value. `del` removes only the selected
  declaration. Both preserve unrelated comments, ordering, multiline values,
  and LF or CRLF line endings.
- Before replacing the encrypted file, mutation commands re-read it and reject
  a detected concurrent change. A non-cooperating writer can still race in the
  narrow interval between that comparison and the atomic replacement.
