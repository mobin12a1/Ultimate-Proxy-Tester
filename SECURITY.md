# Security and privacy

This project probes proxy endpoints you specify. Only test systems you own or
are authorized to assess.

## Credentials

- Keep private proxy lists and authentication details out of public commits.
- Do not paste credentials into bug reports, logs, screenshots or public issues.
- Prefer an access-controlled local `proxies.txt` over command-line `--proxies`
  when credentials are involved; command-line parameters may be recorded.
- The tool writes results to `result.txt` and `result.json`. Review these before
  uploading or sharing.

## Transport

The utility sends network traffic to selected proxies and to third-party
verification endpoints. Some handshake and verification steps use plaintext
HTTP, so the scanner should **not** be described as end-to-end encrypted.

## Dependency and data downloads

Install Python packages from trusted indexes. Optional GeoIP database downloads
come from a third-party distribution; review its source and licensing before use.

## Reporting

If you find a security issue, avoid posting secrets or sensitive target data
in a public GitHub issue. Contact the repository owner privately.
