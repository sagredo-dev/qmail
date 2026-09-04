# Controller password is generated at container start from RSPAMD_PASSWORD env var.
# See docker/rspamd/entrypoint.sh — the hash is written to override.d/ at runtime.
# Do not add a password here; override.d takes precedence.
