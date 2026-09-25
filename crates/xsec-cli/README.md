# xsec-cli

`xsec-cli` encrypts complete dotenv documents with the `xsec` library and
injects their values into child processes without creating a plaintext
temporary file.

The Cargo package is named `xsec-cli`; the installed executable is `xsec`.

## File layout

```text
.env                plaintext input; do not commit
.xsec               encrypted default environment
.xsec.production    encrypted production environment
.xsec.meta          protected data-encryption-key metadata; do not commit
```

The `.xsec` file contains business ciphertext. The `.xsec.meta` file contains
the wrapped data encryption key and protector metadata. Losing `.xsec.meta`
makes the encrypted environment unrecoverable. Back it up and provision it
through an appropriate secret-management channel.

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
xsec env encrypt -i .env -o .xsec
xsec run -f .xsec -- your-command
```

Decrypt to standard output or an explicit file:

```text
xsec env decrypt -i .xsec --stdout
xsec env decrypt -i .xsec -o .env
```

`--stdout` is implicit when `--output` is omitted.

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

The current format encrypts the complete dotenv document. Updating one value
therefore requires decrypting and re-encrypting the document.
