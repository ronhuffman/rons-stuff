# Security and privacy

This is a trusted-LAN hobby monitor, not a safety system. Do not depend on its alerts to prevent appliance damage, fire or other hazards.

## Keep private

Never commit working `pico_config.json`, HA `secrets.yaml`, Wi-Fi credentials, update tokens, complete HA backups, device-state files or unreviewed logs/screenshots. The repository provides examples only. `.gitignore` helps prevent mistakes but does not sanitize source edits or erase previously committed data. Review every staged change before publishing.

Use a different cryptographically random update token for each Pico. The example token is deliberately too short for startup validation. Generate a replacement locally, for example with Python:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Keep the output private. Use a different generated value for each device. Do not reuse the fixed fake tokens in the test fixtures.

## Network boundaries

- OTA uses HTTP bearer authentication without encryption. Anyone able to observe that traffic can capture the token. Use only a trusted private LAN; no port forwarding, public tunnels or untrusted/shared Wi-Fi.
- SHA-256 checks transfer integrity; it is not a digital signature or proof that an application is safe. An authorized payload executes code on the Pico.
- Diagnostic GET endpoints are unauthenticated. Washer `POST /ack` also retains the original unauthenticated LAN interface for HA compatibility. Restrict network access accordingly.
- The washer updater checks both appliance type and individual device identity and binds confirmation to the selected file hash. The dryer 5.0.0 updater does **not** provide equivalent device-identity checks or hash-bound `-ConfirmOnly`. Keep each helper, configuration and application together; do not mix appliance packages or blindly confirm a trial.
- A/B fallback is recovery logic, not protection against all interrupted flash writes, filesystem damage, bad power or loss of the only network path. Keep private backups and a physical recovery plan.

## Publishing changes

The first public snapshot removes installation addresses, coordinates and hardware-specific identifiers. Customizing these example files locally can reintroduce private information. Keep that configured deployment copy outside the public repository or review and sanitize every change before staging it.

If reporting a problem, share a minimal reproduction with fake credentials and identifiers. Do not post access tokens, full configurations or private diagnostic dumps in a public issue.
