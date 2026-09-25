# SECURITY.md

## Authorized-use boundary

SNS Endpoint Security is lawful workplace-monitoring software for **company-owned/managed devices**
operated under a **written, disclosed monitoring policy**. Deployment without such a policy, or on
devices the operator does not own/manage, may be illegal. The software is engineered to make that
boundary enforceable and auditable.

### Explicitly NOT implemented (spec §1)

Keylogging · password/credential capture · browser password/cookie/token extraction · webcam
recording · microphone recording · rootkits · anti-AV / anti-EDR evasion · security-software
bypass · covert persistence · disguising the agent as another Windows component. The service is a
normal, named, discoverable Windows Service (`SNSSecurityAgent`) with a real publisher and an
uninstaller.

## Least privilege

- Service runs as `LocalSystem` (needed for session/USB/screen APIs) but touches only its own
  ProgramData tree and documented Windows APIs.
- Admin panel + CLI run as the invoking user, are read-mostly, and authenticate before any read.
- No child-process spawning of shells; no remote code paths.

## Filesystem access control

Installer sets NTFS ACLs on `C:\ProgramData\SNS\SecurityAgent\`:

- `NT AUTHORITY\SYSTEM` — Full
- `BUILTIN\Administrators` — Full
- `BUILTIN\Users` — **no access** (inheritance disabled)

`keys\` further restricted to SYSTEM + Administrators, and its contents hold **only DPAPI-wrapped**
material.

## Encryption & key management

| Item | Choice |
|---|---|
| Symmetric cipher | AES-256-GCM (`aes-gcm` crate, RustCrypto) |
| Nonce | 96-bit CSPRNG per message (`OsRng`), never reused |
| Data key (DEK) | 256-bit random, generated at install |
| DEK protection | Wrapped with Windows **DPAPI** `CryptProtectData` (LocalMachine scope) |
| At-rest storage | Only the wrapped DEK on disk (`keys/keyring.json`), versioned |
| In memory | Plaintext DEK in `Zeroizing<[u8;32]>`, zeroized on drop/shutdown |
| Rotation | `key_version` per ciphertext; new DEK on rotate; old = decrypt-only |
| Recovery | DEK is host-bound (DPAPI-Machine); loss of host = loss of data by design. Optional escrow is a Phase-2 policy decision, documented not defaulted. |

**Never** log keys, nonces-with-plaintext, or decrypted capture content.

### What is encrypted

- Screenshot blobs (file bodies).
- Sensitive metadata fields flagged in the schema.
- Admin auth secret + integrity-chain HMAC seed.

## Integrity (tamper-evidence)

Each `activity_events` row stores `event_hash = SHA-256(canonical(event) || previous_event_hash)`,
forming a per-device append-only chain (spec §22). `audit_log` is append-only. `sns-agentctl
verify-integrity` recomputes the chain:

```
Events checked: 15,482
Invalid records: 0
Integrity: PASS
```

Any break emits an `INTEGRITY_FAILURE` system event and is surfaced in the admin panel. The chain is
tamper-**evident**, not tamper-proof against a full admin who also rewrites every subsequent hash;
DPAPI host-binding + audit log raise the bar and preserve detectability of casual edits.

## Local admin authentication

- Argon2id password hash (`argon2` crate), per-install random salt.
- Loopback bind (`127.0.0.1`) only; not exposed on any external interface by default.
- Session tokens (random 256-bit), short TTL, `HttpOnly`+`SameSite` cookies, CSRF token on mutations.
- Rate-limited login; failures written to `audit_log`.

## Threat model

See [`ARCHITECTURE.md`](ARCHITECTURE.md#11-threat-model) table. Assets: collected data, screenshots,
DEK, admin creds, integrity chain. Primary defended adversaries: non-admin local user, casual insider
admin tampering, host malware seeking the DEK, network attacker probing the admin port. Out of scope:
kernel/DMA-level attacker (documented).

## Secure SDLC

- `cargo audit` (advisory DB) + `cargo deny` (licenses/bans) in CI.
- `cargo clippy -D warnings`, `#![forbid(unsafe_code)]` where feasible; unsafe confined to a
  reviewed `winapi` shim module.
- Secret scanning (gitleaks) pre-merge.
- Reproducible release build; **Authenticode-signed** binaries + MSI.
- SBOM emitted per release.

## Logging discipline (spec §41)

Log lifecycle/technical events only. Never log passwords, keys, tokens, or captured content. Rotating
logs (size + age capped).
