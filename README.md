# eMudhra Certificate Generator

A command line script that uses the compromised certificate values from the "eMudhra's incident" to create new certificates that have valid chain of trust.

![Random Number](https://imgs.xkcd.com/comics/random_number.png)
[LowByte: The eMudhra Single-Byte CA Key Compromise](https://nelson-dayan.ghost.io/lowbyte-the-emudhra-single-byte-ca-key-compromise/)

## Requirements
  
- Python 3.9 or newer
- OpenSSL available on your `PATH` (check with `openssl version`)

## Project structure 

```
eMudhra Generator/

├── generate_cert.py
├── Certification Genration Files/
│   ├── server.cnf                  # template (uses {DOMAIN_NAME}, {IP_ADDRESS})
│   └── server.ext                  # template (uses {DOMAIN_NAME}, {IP_ADDRESS})
├── Private Keys/
│   └── CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.key
├── Public Certificates/
│   └── CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.pem
└── Intermidiate Certificates/
    └── CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.intermidiate
```
  
## Usage

```
python generate_cert.py <ip> <domain> <validation_level> <generation>
```
  
| Argument | Description | Allowed values |
|---|---|---|
| `ip` | IP address for the certificate | Any valid IPv4 or IPv6 address |
| `domain` | Domain name | A valid domain, wildcards allowed (`*.example.com`) |
| `validation_level` | Validation level | `DV`, `OV`, `EV` (case-insensitive) |
| `generation` | Issuer generation / batch label | `G3B`, `G3C` (case-insensitive) |
  
Example:
  
```
python generate_cert.py 10.0.0.1 example.com DV G3B
```
  
Invalid arguments are rejected with an error message and exit code 2, and nothing is created.
  
## What it does
  
1. Creates a folder next to the script named `{domain}-{ip}-{level}-{generation}`, for example `example.com-10.0.0.1-DV-G3B`.
2. Copies `server.cnf` and `server.ext` into it and replaces `{DOMAIN_NAME}` and `{IP_ADDRESS}` with your values.
3. Runs, inside that folder:
   ```

   openssl genrsa -out server.key 2048
   openssl req -new -key server.key -out server.csr -config server.cnf
   openssl x509 -req -in server.csr -CA <CA .pem> -CAkey <CA .key> -CAcreateserial -CAserial server.srl -out server.crt -days 397 -sha256 -extfile server.ext
   ```
4. Appends the intermediate certificate to `server.crt` (server certificate first, intermediate second) and renames it to `{domain}-{ip}-{level}-{generation}.crt`.
  
The folder is kept after the run. The existing folder is never overwritten: running the script again with the same arguments exits with an error until you remove or rename the old folder.
  
## Output
  
Everything is written to the generated folder:
  
| File | Contents |
|---|---|
| `{domain}-{ip}-{level}-{generation}.crt` | Server certificate followed by the intermediate certificate |
| `server.key` | Private key for the certificate (not encrypted) |
| `server.csr` | Certificate signing request |
| `server.cnf`, `server.ext` | Filled-in configuration files |
| `server.srl` | Serial number file used for this run |
  
To use the result with a server, copy the `.crt` and `server.key` **from the same generated folder** (for example as `server.crt` and `server.key`). Mixing files from different runs causes a key mismatch error such as `KEY_VALUES_MISMATCH`.
  
## How the CA files are chosen
  
The CA name is built from the arguments, for example `DV` + `G3B` gives `CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL`.
  
| Generation | Issuer part of the name |
|---|---|
| `G3B` | `O=eMudhra BV,C=NL` |
| `G3C` | `O=eMudhra Inc,C=US` |
  
The script then looks for:
  
- `Private Keys/<CA name>.key`
- `Public Certificates/<CA name>.pem` (signs the certificate)
- `Intermidiate Certificates/<CA name>.intermidiate` (appended to the certificate)
  
OV uses the `OV TLS CA` files. The `OV CS CA` files are not used.
  
If a file is missing, the script stops and prints the exact path it expected.
  
## Notes
  
- Keep the `Private Keys` folder and generated `server.key` files private, and do not commit them to version control.
- Certificates are valid for 397 days. Change `CERT_VALIDITY_DAYS` in the script to adjust this.
- In folder names, `*` (wildcard domains) is written as `wildcard` and `:` (IPv6) as `-`, because Windows does not allow those characters.
- Folder and file names are case-sensitive on Linux and macOS, so they must match the script exactly.
  
## Troubleshooting
  
| Message | Cause |
|---|---|
| `... is not a valid IP address` / `... is not a valid domain name` | An argument failed validation |
| `invalid choice ... (choose from ...)` | Validation level or generation is not one of the allowed values |
| `temporary folder already exists` | A folder with the same name is already there |
| `CA file not found` / `intermediate certificate not found` | A CA file is missing or named differently than expected |
| `openssl was not found on PATH` | OpenSSL is not installed or not on your `PATH` |
| `command failed (exit N)` | An `openssl` command failed; the message includes OpenSSL's own error output |
  
## References

- https://scotthelme.co.uk/eight-bits-of-trust-emudhras-ca-keys-cracked-in-milliseconds/
- https://emudhra.we-have-a-problem.com/
- https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE/m/Kp1v6CPuAAAJ?utm_source=scotthelme.co.uk
