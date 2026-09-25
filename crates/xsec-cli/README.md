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
.xsec.meta          protected data-encryption-key metadata; do not commit
```

The `.xsec` file remains a dotenv document: variable names, comments, ordering,
and blank lines stay readable, while protected values use the
`encrypted:xsec:<base64>` format. The `.xsec.meta` file contains the wrapped
data encryption key and protector metadata. Losing `.xsec.meta` makes the
encrypted values unrecoverable. Back it up and provision it through an
appropriate secret-management channel.

## Usage

Initialize password-protected metadata:

```text
xsec init
```

The password is read from the terminal without echoing. For non-interactive
use, pass it through standard input:

```text
printf '%s' "$XSEC_PASSWORD" | xsec init --password-stdin
```

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
xsec set API_TOKEN value -f .xsec
xsec set API_TOKEN -f .xsec
printf '%s' "$API_TOKEN" | xsec set API_TOKEN --stdin -f .xsec
xsec del API_TOKEN -f .xsec
```

`set` accepts a dotenvx-style positional value. Omit it to prompt without echo,
or use `--stdin` to keep the value out of the process argument list and shell
history. Standard input is stored exactly, including terminal newlines, and
may be empty. A value cannot contain NUL or carriage-return bytes. `get` writes
only the value, without a label or added newline. `get` and `del` exit with
status 1 when the key is absent.

On a supported platform, system protection requires a stable logical identity:

```text
xsec init --protector system --identity your-project-id
xsec run --protector system --identity your-project-id -- your-command
```

Do not derive this identity from an absolute path. Moving the project must not
change the identity.

## Runtime behavior

- Existing process environment variables take precedence by default.
- `--override` lets values from the encrypted file replace existing values.
- Duplicate variable names and malformed dotenv input are rejected.
- Missing metadata, failed authentication, and unsupported system protection
  are fatal. The CLI never falls back to a plaintext `.env` file.
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
