# EB Sessions Sync: Protocol Specification and Threat Model

Status: draft, protocol version 1 (`ebs/v1`)
Date: 2026-10-29
Audience: the implementer of the server (separate repository, Cloudflare Worker + D1) and the implementer of the client (inside the EB Sessions Chrome MV3 extension). Both MUST be able to build an interoperable implementation from this document alone.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

---

## Table of contents

1. Overview
2. Terminology
3. Conventions and encodings
4. Cryptographic profile
5. Key hierarchy
6. Client key and token storage
7. Identities, roles and profiles
8. Records
9. Membership log
10. Flows
11. API
12. D1 schema
13. Logging and audit
14. Threat model
15. Client integration notes
16. GDPR
17. Open questions
18. Teamwerk (live presence)
19. Summary of design choices
20. Appendix A. Test vectors

---

## 1. Overview

### 1.1 What this is

EB Sessions is a Chrome MV3 extension that enhances the Dutch bookkeeping web app e-Boekhouden. Several of its features keep small pieces of state: import groups, hidden bank lines, AI classifications per bank line, the reminder ladder mapping, and per-screen preferences. Today this state lives in `chrome.storage.local` on one machine. EB Sessions Sync lets that state follow the user to other devices and lets colleagues who work in the same e-Boekhouden administration share it.

### 1.2 Goals

- G1. End-to-end encryption. The server stores ciphertext only. The server and its operator can never read record contents, record names, or the e-Boekhouden administration number.
- G2. The server knows identities (accounts, devices) and access rights (which user may access which profile). Nothing more about the data than unavoidable metadata (section 14.4).
- G3. Multi-user. Several users can share a profile. Several profiles can exist for the same administration.
- G4. Detect a server that adds members or devices on its own (signed membership log, device codes).
- G5. Revocation that actually stops future access (key rotation with lazy re-encryption).
- G6. Self-hostable on a Cloudflare free or paid account with a deploy button. Open source.
- G7. GDPR friendly: export, deletion, minimal logging.
- G8. One-click connection from the extension (OAuth 2.0 authorization code with PKCE via `chrome.identity.launchWebAuthFlow`).
- G9. Live "Teamwerk" presence between members of a profile who are online at the same time, end-to-end encrypted, behind the extension setting "Teamwerk" (off by default), never stored (section 18).

### 1.3 Non-goals

- Real-time collaboration. Last-write-wins per record is acceptable.
- Hiding the social graph (who shares with whom) from the server.
- Protecting data on a device that is unlocked and in the hands of an attacker.
- Syncing large blobs. Records are under 64 KiB.
- Protecting against a malicious extension build. The extension code is trusted; it is distributed through the Chrome Web Store, never by the sync server.

### 1.4 Components

```
+-------------------------------+          HTTPS           +------------------------------------+
| Chrome profile                |                          | Cloudflare Worker "ebs-sync"       |
|                               |                          |                                    |
|  e-Boekhouden tab             |                          |  /oauth/*     OAuth AS (PKCE)      |
|   page JS (untrusted)         |                          |  /v1/*        JSON API             |
|   content scripts             |                          |  /            dashboard (static)   |
|     | runtime.sendMessage     |                          |  cron         retention jobs       |
|     v  (store ops only)       |   device token + ECDSA   |                                    |
|  service worker  -------------+------------------------->|  D1 (SQL)  accounts, devices,      |
|   sync engine, keys, tokens   |    request signatures    |            profiles, logs, wraps,  |
|  options page / popup         |                          |            ciphertext, audit       |
|   "Verbinden", profiles,      |  launchWebAuthFlow       |                                    |
|   approvals, recovery, export +------------------------->|  Email provider (login, invites)   |
+-------------------------------+                          +------------------------------------+
                                                             ^
                                       browser (passkey)     |
                                       dashboard user -------+
```

The dashboard is a static single-page app served by the same Worker, on the same origin as the API. It holds no encryption keys. Every operation that needs a data key (creating a profile, approving access, rotating keys, decrypting) happens in the extension.

### 1.5 Design summary in one paragraph

Each profile has a random 256-bit data key (DK) and a random 256-bit naming key (NK). Each device has a non-extractable ECDH P-256 key and a non-extractable ECDSA P-256 key, kept in IndexedDB of the extension origin. DK and NK are wrapped per device with ephemeral-static ECDH, HKDF-SHA-256 and AES-256-GCM, and every wrap is signed by the device that made it. Records are AES-256-GCM encrypted with a random 96-bit nonce and associated data that binds profile id, record id, key version, record version and the delete flag. Record ids are HMAC-SHA-256 of the logical name under a key derived from NK. A hash-chained membership log, signed entry by entry by member devices, is the source of truth for who holds the keys. A new device or user gets access only after an existing member device approves it, ideally after comparing a 100-bit device code. Removing a device or user appends a removal and a key rotation; any remaining member re-encrypts old records lazily in rate-limited batches. A printed recovery key (128 bits, PBKDF2-SHA-256 600,000 iterations) protects a per-user recovery pseudo-device so that a single user who loses all devices can recover.

---

## 2. Terminology

| Term | Meaning |
|------|---------|
| Instance | One deployment of the Worker and its D1 database. |
| Operator | Whoever controls the Cloudflare account of an instance. Can read and modify D1 and the Worker code. |
| Admin (beheerder) | A user with the instance-level `admin` flag. Manages accounts and server-side access in the dashboard. Usually the operator. |
| User | An account, identified by `user_id`, with a verified email address and a display name. |
| Passkey | A WebAuthn credential used to log in to the dashboard and the connect page. |
| Session | A dashboard login session (cookie). |
| Device | One installation of the extension in one Chrome profile, identified by `device_id`, with its own key pairs and one device token. |
| Recovery device | A pseudo-device whose private keys are encrypted under a printed recovery key. One per user at most. |
| Device token | Opaque bearer secret identifying a device to the API. The "API key" per device. Always used together with a request signature. |
| Device code | 100-bit fingerprint of a device's public keys, shown as 20 characters. Compared by humans to defeat key substitution. |
| Administration | One e-Boekhouden administration, identified in e-Boekhouden by a number (`administration number`). |
| Profile | The unit of data, membership and encryption. Belongs to exactly one administration and one owning user. Has its own DK and NK. Replaces the earlier "workspace" notion. |
| Owner (eigenaar) | The one user who owns a profile. |
| Member (lid) | A user other than the owner who has access to a profile. |
| Grant | Server-side authorization for a user to access a profile. Created by an admin or the profile owner. Starts as `pending` until a member device approves it cryptographically. |
| Approval | The client action that wraps DK and NK for a pending device and appends a signed `add_device` log entry. |
| DK | Data key of a profile, 32 random bytes, versioned by `kv`. |
| NK | Naming key of a profile, 32 random bytes, never rotated in v1. |
| kv | Key version, integer starting at 1. Incremented by every rotation. |
| Wrap | DK and NK of one key version, encrypted for one device. |
| Record | One encrypted JSON value stored under an opaque record id within a profile. |
| Logical key | The plaintext name the extension uses for a record, for example `hiddenLines/8812345`. |
| Record id (rid) | `HMAC(K_rid, logical key)`, opaque to the server. |
| Tombstone | A record with `deleted = true`. Its ciphertext is an encrypted tombstone payload. |
| Cursor | Opaque string returned by the server; marks how far a client has pulled a profile's changes. |
| seq | Server-assigned, strictly increasing change counter per profile. The cursor encodes it. |
| Membership log | Hash-chained, signed, append-only list of membership and key events of a profile. |
| Head | `(seq, hash)` of the last entry of a membership log. |
| Teamwerk | Live presence: route, cursor, focus and status of colleagues in the same profile (section 18). |
| Room | The Durable Object that relays Teamwerk frames for one profile. |
| Room ticket | Short-lived, single-use credential that authorizes one WebSocket connection to a room. |
| Presence key | `K_pres(kv)`, derived from `DK_kv`; per-connection keys `K_sess` are derived from it. |

Two different counters are both called "seq" in casual speech. This document always writes `log seq` for the membership log position and `change seq` for the record change counter.

---

## 3. Conventions and encodings

### 3.1 Binary encodings

- `b64u(x)`: base64url without padding (RFC 4648 section 5). All binary values in JSON use this encoding. Decoders MUST reject padding and non-alphabet characters.
- `u8(n)`, `u32(n)`, `u64(n)`: unsigned big-endian integers of 1, 4 and 8 bytes.
- `utf8(s)`: UTF-8 encoding of a string, without BOM. Strings MUST be valid Unicode scalar sequences.
- `enc(x1, ..., xn)`: length-prefixed concatenation. For each item: `u32(len(xi)) || xi`. Strings are encoded with `utf8` first; integers are encoded with the width stated at the call site. `enc` is used for every signature input, HKDF info, associated data and hash input in this document, so that no two different tuples can produce the same bytes.
- `H(x)`: SHA-256.
- `Z32`: 32 zero bytes.
- Public keys are the uncompressed SEC1 point (65 bytes, first byte `0x04`), as produced by WebCrypto `exportKey("raw", publicKey)`.
- ECDSA signatures are IEEE P1363 `r || s` (64 bytes), the WebCrypto output format. Implementations on platforms that produce DER MUST convert.

### 3.2 Canonical JSON (JCS profile)

Signed JSON objects (membership log entries) are serialized with RFC 8785 (JCS), restricted to this profile so that a ten-line implementation is correct:

- Allowed values: objects, arrays, strings, `true`, `false`, `null`, and integers in `[0, 2^53 - 1]`. No floats, no negative numbers.
- Object keys are ASCII and unique.
- Serialization: no whitespace; object members sorted by key (ASCII byte order); strings serialized exactly as ECMAScript `JSON.stringify` does.

In JavaScript, `jcs(v)` is: if `v` is an array, `"[" + v.map(jcs).join(",") + "]"`; if it is a non-null object, `"{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}"`; otherwise `JSON.stringify(v)`. Servers and clients MUST reject entries that contain values outside the profile.

### 3.3 Identifiers

| Kind | Format | Generated by |
|------|--------|--------------|
| `user_id` | `u_` + b64u(16 random bytes) | server |
| `device_id` | `d_` + b64u(16 random bytes) | server, at registration |
| `profile_id` | `p_` + b64u(16 random bytes) | client (needed inside the genesis entry before the server sees the profile) |
| `grant_id` | `g_` + b64u(16 random bytes) | server |
| record id | b64u(32-byte HMAC), 43 characters | client |
| other ids (passkey, invite, audit) | prefix + b64u(16 random bytes) | server |

All random values MUST come from a CSPRNG (`crypto.getRandomValues` in browsers and Workers). Ids are case sensitive.

### 3.4 Time

All timestamps are integers in Unix milliseconds (UTC) unless a field name ends in `_s` (seconds). The server is the time authority for expiry. Client clocks are used for last-write-wins ordering (the hybrid clock in 8.6), for request signature timestamps (11.2) and for Teamwerk freshness (18.15).

Clock skew: every API response carries `EBS-Server-Time: <Unix ms>`. The client keeps `offset = server_time - local_time` (updated on each response, smoothed) and uses `local_time + offset` for `EBS-Timestamp` and for the Teamwerk `ts` field. `401 invalid_signature` responses caused by the time window carry `details.server_time`, after which the client updates the offset and retries once. The hybrid clock uses the corrected time too.

### 3.5 Labels

Domain separation labels are ASCII strings starting with `ebs/v1/`. A future protocol version uses new labels; nothing derived under `ebs/v1/` is ever reused under another label.

### 3.6 Interoperability definitions

- `enc` items are typed by position, not self-describing: `enc(u32(0x41414141))` and `enc("AAAA")` produce identical bytes. This is safe because every call site in this document has a fixed sequence of item types, and every call starts with a distinct label string.
- Lengths of strings that carry a limit ("at most 64 characters") count Unicode code points after NFC normalization. Display strings (labels, names, device names) are NFC-normalized by the client before use; logical keys, ids and URLs are never normalized.
- base64url decoders MUST reject padding, non-alphabet characters and non-zero unused trailing bits, so every value has exactly one encoding.
- Hex in this document is lower case. Byte strings in test vectors are big-endian.
- JSON integers MUST be in `[0, 2^53 - 1]`. JSON parsers MUST reject duplicate keys in every signed or encrypted structure (log bodies, payloads, meta, names).
- Public keys MUST be imported with WebCrypto `importKey("raw", ...)`, which rejects points not on the curve; servers MUST apply the same check.
- ECDSA signatures are not unique: for a valid `(r, s)`, `(r, n - s)` also verifies. Nothing in this protocol hashes or deduplicates signature bytes (9.1); signatures are only verified.
- `platform` is one of `mac`, `win`, `linux`, `cros`, `other`, derived by the client from `navigator.userAgentData.platform` or `navigator.platform`.
- Display strings (profile labels, user names, device names) MUST NOT contain C0 or C1 control characters or the bidirectional override and isolate characters U+202A to U+202E and U+2066 to U+2069. Leading and trailing whitespace is trimmed and internal runs of whitespace are collapsed to one space. Servers reject strings that violate this with `400 invalid_request`; clients validate before sending and again before rendering.


---

## 4. Cryptographic profile

The client uses only primitives available in WebCrypto in Chrome 116 (the extension's `minimum_chrome_version`) and in the Cloudflare Workers runtime. Suite identifier: `p256-v1`.

| Purpose | Primitive | Parameters | Why this one |
|---------|-----------|------------|--------------|
| Key agreement for wraps | ECDH P-256 | static device key, ephemeral sender key, `deriveBits` 256 | Available in every Chrome version the extension supports, works with non-extractable private keys, and the Worker can verify nothing it does not need to. X25519 reached Chrome WebCrypto only recently and is not guaranteed at Chrome 116. |
| Signatures (log entries, wraps, API requests, token proof) | ECDSA P-256 with SHA-256 | P1363 encoding | Same reasoning; one curve for the whole suite keeps implementations small. WebCrypto uses a proper RNG, so ECDSA nonce reuse is not a practical concern. Ed25519 (deterministic, smaller) is reserved for a future suite `x25519-ed25519-v2` once the minimum Chrome version guarantees it. |
| Key derivation | HKDF-SHA-256 | salt and info as specified per key | Standard extract-then-expand; clean domain separation of subkeys from one root. |
| Record, meta, wrap and history encryption | AES-256-GCM | 96-bit random nonce, 128-bit tag | Hardware accelerated, AEAD with associated data, native in WebCrypto. |
| Record ids, key commitments | HMAC-SHA-256 | 256-bit key | Deterministic PRF: same logical key gives the same id on every member device, without revealing the name. |
| Recovery key stretching | PBKDF2-HMAC-SHA-256 | 600,000 iterations, 16-byte random salt, 256-bit output | The only password KDF in WebCrypto (no Argon2 or scrypt). The recovery key already has 128 bits of entropy, so the iterations are not what protects it; they are applied anyway so the stored format is safe if a future version allows human passphrases, and the cost (well under a second on a desktop) is paid only when creating or using a kit. |
| Teamwerk frames | AES-256-GCM under a per-connection key `K_sess` (HKDF from `K_pres`), counter nonce, plus a per-frame ECDSA P-256 signature | `nonce = u32(0) \|\| u64(seq)` | A fresh key per connection makes counter nonces safe at high frame rates; the signature attributes every cursor and marker to a device in the signed log (18.7). |
| Hashing | SHA-256 | | Hash chain, device codes, PKCE, token hashes. |

### 4.1 Nonce budget

AES-GCM with random 96-bit nonces is safe for up to 2^32 encryptions per key. Every record write, meta update and history blob under one `K_rec(kv)` counts. The server counts writes per `(profile, kv)` and sets `rotation_recommended = true` in the profile state when the count exceeds 2^30. Clients that see this flag SHOULD perform a rotation (section 10.14 without a removal). With tens of thousands of records this limit is not expected to be reached.

### 4.2 Algorithm agility

Every wrap, log body and recovery blob carries `"v": 1`. The suite is fixed per protocol version. A server that does not support a client's version answers `426 upgrade_required` (section 11.3).

---

## 5. Key hierarchy

### 5.1 Diagram

```
 PER DEVICE (one Chrome profile)                    PER USER (optional)
 ===============================                    ====================
 ECDH P-256 key pair      ECDSA P-256 key pair      recovery key (printed, 128 bit)
   ecdh_priv (non-extr.)    sign_priv (non-extr.)       | PBKDF2-SHA-256, 600k, salt
   ecdh_pub                 sign_pub                    v
      |                        |                    K_rk_kek (AES-GCM)
      |                        +--> signs log entries,  |  decrypts
      |                             wraps, requests     v
      |                                             recovery device private keys
      |                                             (ECDH + ECDSA, PKCS#8), acts as
      |                                             a normal device in every log
      |
      |  ECDH(eph_priv, ecdh_pub) -> HKDF -> KEK
      v
 PER PROFILE, PER KEY VERSION kv
 ===============================
 Wrap(kv, device) = AES-GCM(KEK, NK || DK_kv), signed by the wrapping device

     NK (32 B, constant per profile)            DK_kv (32 B, rotated on removal)
       |                                          |
       | HKDF info "ebs/v1/rid"                   +-- HKDF "ebs/v1/rec"    -> K_rec(kv)    AES-GCM: records
       v                                          +-- HKDF "ebs/v1/meta"   -> K_meta(kv)   AES-GCM: profile meta
     K_rid  HMAC: record id = HMAC(K_rid, key)    +-- HKDF "ebs/v1/hist"   -> K_hist(kv)   AES-GCM: DK_(kv-1)
       |                                          +-- HKDF "ebs/v1/commit" -> K_commit(kv) HMAC: dk_commit(kv)
       +-- HKDF "ebs/v1/nk-commit" -> nk_commit
                                                   History chain (server-stored):
                                                   DK_n --K_hist(n)--> DK_(n-1) --K_hist(n-1)--> ... --> DK_1
```

A device that holds a wrap for the current `kv` can reach every older DK through the history chain, so a device that joins after a rotation needs only one wrap. A removed device never receives `DK_(kv+1)` and cannot walk the chain forward.

### 5.2 Derivations

For profile id `p` (UTF-8 string) and key version `kv`:

| Key | Derivation | WebCrypto usage |
|-----|------------|-----------------|
| `K_rec(kv)` | `HKDF(ikm = DK_kv, salt = Z32, info = enc("ebs/v1/rec", p, u32(kv)), L = 32)` | AES-GCM, encrypt/decrypt |
| `K_meta(kv)` | `HKDF(DK_kv, Z32, enc("ebs/v1/meta", p, u32(kv)))` | AES-GCM |
| `K_hist(kv)` | `HKDF(DK_kv, Z32, enc("ebs/v1/hist", p, u32(kv)))` | AES-GCM |
| `K_commit(kv)` | `HKDF(DK_kv, Z32, enc("ebs/v1/commit", p, u32(kv)))` | HMAC-SHA-256 |
| `dk_commit(kv)` | `b64u(HMAC(K_commit(kv), enc("ebs/v1/dk-commit", p, u32(kv))))` | value in the log |
| `K_rid` | `HKDF(NK, Z32, enc("ebs/v1/rid", p))` | HMAC-SHA-256 |
| `rid(name)` | `b64u(HMAC(K_rid, utf8(name)))` | record id |
| `K_nkc` | `HKDF(NK, Z32, enc("ebs/v1/nk-commit", p))` | HMAC-SHA-256 |
| `nk_commit` | `b64u(HMAC(K_nkc, enc("ebs/v1/nk-commit", p)))` | value in the genesis entry |
| `K_name` | `HKDF(NK, Z32, enc("ebs/v1/name", p))` | AES-GCM, display names in the log (9.3) |
| `K_pres(kv)`, `K_sess`, `K_focus` | see 18.6 | Teamwerk only |

In WebCrypto: import `DK_kv` (or `NK`) with `importKey("raw", bytes, "HKDF", false, ["deriveKey", "deriveBits"])`, then `deriveKey({name: "HKDF", hash: "SHA-256", salt, info}, base, {name: "AES-GCM", length: 256} or {name: "HMAC", hash: "SHA-256", length: 256}, false, usages)`. Derived keys are non-extractable.

`dk_commit` and `nk_commit` let every member verify that the DK and NK it unwrapped are the ones the signed log declares, so a malicious member or server cannot hand different devices different keys for the same version without detection.

### 5.3 Wrap format

A wrap carries `NK || DK_kv` (64 bytes) for one profile, one key version and one recipient device.

Creation by device `from` for recipient device `to` (public key `ecdh_pub_to`), authorized by log entry at log seq `at` (section 9.5):

1. Generate an ephemeral ECDH P-256 key pair `(eph_priv, eph_pub)`, extractable public part only.
2. `Z = ECDH(eph_priv, ecdh_pub_to)`, 32 bytes (`deriveBits`, length 256).
3. `KEK = HKDF(ikm = Z, salt = H(enc(eph_pub, ecdh_pub_to)), info = enc("ebs/v1/wrap", p, u32(kv), to, from), L = 32)` as AES-GCM-256.
4. `nonce` = 12 random bytes.
5. `aad = enc("ebs/v1/wrap-aad", p, u32(kv), to, from, u64(at), eph_pub)`.
6. `ct = AES-GCM-Encrypt(KEK, nonce, NK || DK_kv, aad)` (80 bytes).
7. `sig = ECDSA-Sign(sign_priv_from, enc("ebs/v1/wrap-sig", p, u32(kv), to, from, u64(at), eph_pub, nonce, ct))`.
8. Discard `eph_priv`, `Z`, `KEK` and the plaintext buffer.

Wire format:

```json
{
  "v": 1,
  "profile_id": "p_...",
  "kv": 3,
  "to": "d_...",
  "from": "d_...",
  "at": 17,
  "epk": "<b64u 65 bytes>",
  "nonce": "<b64u 12 bytes>",
  "ct": "<b64u 80 bytes>",
  "sig": "<b64u 64 bytes>"
}
```

Verification by the recipient (all steps MUST pass, else the wrap is rejected and the client shows a security warning):

1. The client has a verified membership log for `p` up to at least log seq `at`.
2. The entry at `at` is either an `add_device` entry adding `to` while the profile was at `kv`, or a `rotate_key` entry introducing `kv` (and `to` is active right after it), or a `genesis` entry with `kv = 1` that includes `to`.
3. `from` is the author of that entry.
4. `sig` verifies under `from`'s `sign_pub` as recorded in the log.
5. Decryption succeeds.
6. `dk_commit(kv)` computed from the unwrapped DK equals the value in the log for `kv`, and `nk_commit` equals the genesis value.

### 5.4 History blob

On rotation from `kv - 1` to `kv`, the rotating device stores:

```json
{ "v": 1, "profile_id": "p_...", "kv": 4, "nonce": "<b64u 12>", "ct": "<b64u 48>" }
```

with `ct = AES-GCM-Encrypt(K_hist(kv), nonce, DK_(kv-1), enc("ebs/v1/hist-aad", p, u32(kv)))`. A client that needs `DK_j` for `j < kv` decrypts the chain downward and checks `dk_commit(j)` at each step. History blobs are not signed: only holders of `DK_kv` can create them, and the commitment check detects substitution.

### 5.5 Recovery key and recovery device

- Recovery key: 16 random bytes `rk` plus a 4-byte checksum `c = H(enc("ebs/v1/rk-check", rk))[0..4]`. The 20 bytes are encoded as 32 Crockford base32 characters (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 5 bits per character, big-endian bit order) and displayed in 8 groups of 4: `7K3M-QX2A-...`. Input is case insensitive; `O` is read as `0`, `I` and `L` as `1`; hyphens and spaces are ignored. The checksum lets the client say "typefout" before running the KDF.
- `salt` = 16 random bytes. `iterations` is pinned to exactly 600,000 in protocol version 1: clients MUST refuse to run PBKDF2 with any other value from a blob, and the server MUST reject other values. This stops a malicious server from making a recovering client run an enormous iteration count, and keeps the format unambiguous.
- `S = PBKDF2-HMAC-SHA-256(rk, salt, 600000, 256 bits)`.
- `K_rk_kek = HKDF(S, Z32, enc("ebs/v1/rk-kek", user_id, recovery_device_id))` as AES-GCM-256.
- The recovery device has its own ECDH and ECDSA key pairs, generated as extractable, exported as PKCS#8 and raw public keys, encrypted once, and then dropped from memory:
  `pt = utf8(jcs({"ecdh_pkcs8": b64u(..), "sign_pkcs8": b64u(..), "ecdh_pub": b64u(..), "sign_pub": b64u(..)}))`, `ct = AES-GCM-Encrypt(K_rk_kek, nonce, pt, enc("ebs/v1/rk-aad", user_id, recovery_device_id))`.
  The public keys are inside the plaintext because a private key imported as non-extractable cannot be used to export its public key; the recovering client needs them to check that the decrypted keys belong to the recovery device in the log.
- `test_sig = ECDSA-Sign(recovery sign_priv, enc("ebs/v1/rk-test", user_id, recovery_device_id, sign_pub, ecdh_pub))`, made at creation, shows that the holder of the recovery signing key endorsed this ECDH key.
- `attest_sig = ECDSA-Sign(creating device sign_priv, enc("ebs/v1/rk-attest", user_id, recovery_device_id, sign_pub, ecdh_pub, salt, nonce, H(ct)))` lets the user's other devices decide whether to trust the recovery device (10.16).
- Stored on the server: `{v, user_id, recovery_device_id, sign_pub, ecdh_pub, salt, iterations, nonce, ct, test_sig, attest: {device_id, sig}}`.

Because the recovery device is a normal device in each log, rotations wrap the new DK for it automatically and the printed kit never has to be reprinted after a rotation. Its private keys exist in plaintext only during kit creation and during recovery, on the device doing it.

### 5.6 Device code (fingerprint)

`dc_full = H(enc("ebs/v1/device-code", sign_pub, ecdh_pub))`.

The device code is the first 100 bits of `dc_full`, encoded as 20 Crockford base32 characters and shown in 5 groups of 4 separated by spaces: `K7QM 2XPA 9RTD W4HE 8NBC`.

`device_jkt = b64u(dc_full)` (all 32 bytes) is used in the OAuth flow to bind an authorization code to the device keys.

Why 100 bits and no commit-and-reveal short code: approvals are asynchronous (the requester and the approver are often not online at the same time), so the comparison string must resist offline grinding by a malicious server that generates key pairs until a prefix matches. 100 bits needs about 2^100 key generations for a second preimage, which is infeasible. A 6-digit code would need an interactive commitment protocol with both parties online, which conflicts with the one-click approval the product requires.

---

## 6. Client key and token storage

### 6.1 Where secrets live

Secrets MUST only be handled by the service worker and by extension pages (options page, popup, the recovery and export pages). Content scripts and page context MUST NOT receive keys, wraps, tokens, request signatures or any API response that contains them.

| Item | Location | Notes |
|------|----------|-------|
| `sign_priv`, `ecdh_priv` | IndexedDB database `ebs-sync`, store `device`, as non-extractable `CryptoKey` objects | Generated with `extractable = false`. |
| `sign_pub`, `ecdh_pub` (raw) | same record | Public. |
| `device_id`, device token | same record | Token as a string. |
| Wrap blobs, history blobs | IndexedDB store `keys` | Useless without `ecdh_priv`. Cached so the extension works offline. |
| Derived keys `K_rec(kv)`, `K_meta(kv)`, `K_rid` | IndexedDB store `keys`, non-extractable `CryptoKey` | A cache; can be re-derived from wraps. |
| Raw `NK`, `DK_kv` bytes | Service worker memory only, transiently | Needed only when wrapping for another device or creating a history blob; zeroed (`fill(0)`) after use. Never persisted. |
| Verified log state per profile | IndexedDB store `profiles` | Includes head, devices, roles, kv, commits. |
| Plaintext record cache and outbox | IndexedDB stores `records`, `outbox` | Same at-rest exposure as today's local backend. |
| OAuth `state`, PKCE `code_verifier` during connect | `chrome.storage.session` | Access level `TRUSTED_CONTEXTS` (already set by `src/background.js`). Deleted when the flow ends. |
| Server URL, sync enabled flag, last sync time | `chrome.storage.local` | Non-secret only. |

### 6.2 Why not `chrome.storage.local` for keys and tokens

1. `CryptoKey` objects are not JSON serializable, so a non-extractable key cannot be stored in `chrome.storage.local` at all. Storing it there would require making it extractable and storing a JWK, which defeats non-extractability.
2. `chrome.storage.local` is readable by content scripts. A content-script bug that can be steered by a hostile e-Boekhouden page would then leak the token and keys. IndexedDB opened from the service worker or an extension page belongs to the `chrome-extension://<id>` origin; content scripts run in the page origin and cannot open it.

### 6.3 What non-extractable does and does not give

It prevents export through the WebCrypto API, so a script bug in an extension page cannot copy the private key off the machine (it can still use the key while it runs). It does not encrypt key material on disk: Chrome stores IndexedDB unencrypted inside the user profile. Disk-level protection relies on OS disk encryption (FileVault, BitLocker). This is a documented residual risk (section 14.5).

### 6.4 Key generation at first connect

```
ecdh = crypto.subtle.generateKey({name: "ECDH", namedCurve: "P-256"}, false, ["deriveBits"])
sign = crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, false, ["sign"])
ecdh_pub = exportKey("raw", ecdh.publicKey); sign_pub = exportKey("raw", sign.publicKey)
```

Separate key pairs for agreement and signing are required by WebCrypto key usages and are good key separation practice. A device never rotates its key pairs in v1; a compromised device is removed and reconnected as a new device.

---

## 7. Identities, roles and profiles

### 7.1 Roles

| Role | Scope | Stored | Can |
|------|-------|--------|-----|
| `admin` | instance | `users.is_admin` (server only) | Create and disable accounts, send set-up links, grant and revoke users' access to any profile (server-side), view all profiles' metadata, delete profiles, view the instance audit log, configure instance policies. Cannot decrypt anything. |
| `owner` | profile | membership log and server | Everything a member can do, plus grant and revoke access, change the profile policy, rename, delete the profile, transfer ownership. Exactly one per profile. |
| `member` | profile | membership log and server | Read and write records, approve pending access (unless the policy says owner only), add and remove own devices, leave. |

Server-side authorization (what the API lets a token or session do) and cryptographic authorization (who holds the keys, per the log) are separate layers. A request touching profile data needs both: the server's grant must be `active` and the device must be `active` in the profile (which the server only marks after accepting a signed `add_device` entry).

### 7.2 Profiles

- A profile belongs to exactly one administration and one owning user.
- Several profiles MAY exist for the same administration, owned by the same or different users ("two separate accounts each with their own data for the same administration").
- A profile has a plaintext `label` (default `Mijn profiel`, at most 64 characters, display string rules of 3.6) so that the dashboard and the switcher can show it. The client MUST tell the user, where the label is edited, that the label is visible to the server operator. Before saving, the client warns "Dit label is zichtbaar voor de beheerder van de server en lijkt een administratienummer of bedrijfsnaam te bevatten" when the label consists only of digits, or contains (case-insensitively, after NFC) the administration number or the administration name from the profile meta. The user may save anyway.
- A profile has an encrypted `meta` blob (section 8.7) that contains the administration number and optional display data. The server never sees the administration number.
- A profile has a policy, set in the signed log: `approvers` (`members` default, or `owner`) and `auto_approve` (`false` default).

### 7.3 Mapping administrations to profiles: decision

The client needs "which profiles belong to the administration open in this tab". Three options were weighed:

| Option | Server learns | Enumeration risk | Usability | Verdict |
|--------|---------------|------------------|-----------|---------|
| A. Server stores `HMAC(server_pepper, administration number)` | A stable tag per administration; which profiles share an administration, across all users | The server holds the pepper. Administration numbers are short numbers (a space of at most a few million values), so the operator reverses every tag in well under a second. A D1 leak without the pepper is safe, but the operator is exactly the party G1 excludes. | Best: one indexed lookup. | Rejected. |
| B. Server stores `HMAC(per-user secret, administration number)` plus a client-side list | Which of one user's profiles share an administration | Not enumerable by the server. | Needs a per-user secret synced to all of the user's devices (a second key distribution problem), and does not help a member of a shared profile, whose own secret produces a different tag. | Rejected: extra machinery, little gain over C. |
| C. Encrypted `meta` per profile; the client lists all profiles it can access, decrypts each `meta` and builds the index locally | Nothing about the administration | None. | One request (`GET /v1/profiles` returns `meta` ciphertext inline) plus one AES-GCM decryption per profile, cached and refreshed only when `meta_version` changes. Fine up to about a thousand profiles per user, which covers accountants with many client administrations. | Chosen. |

Consequences of option C:

- The dashboard cannot show which administration a profile belongs to. It shows the label, owner, member count and dates.
- A user whose grant is still pending cannot know the administration of that profile (they have no key yet). The extension shows the pending profile with its label and owner name in the popup regardless of the current administration.
- The local index (`administration number -> [profile_id]`) lives in IndexedDB `profiles` on each device.

### 7.4 Active profile per administration

Each device remembers, per administration number, the active profile (IndexedDB `activeProfileByAdministration`). The popup and the navbar menu inside e-Boekhouden offer a profile switch when more than one profile is accessible for the current administration. Switching changes which profile the `sync` backend reads and writes for that administration on that device only. Rules:

1. If exactly one accessible profile exists for the administration, it is active.
2. If several exist and none is remembered, the most recently used on this device is active; if none was used, the one the user owns; else the oldest. The switcher is shown with a notice the first time.
3. If none exists and the user writes to a sync-backed namespace, the extension creates a profile `Mijn profiel` for that administration (flow 10.7) after the user enabled sync for that administration once.

---

## 8. Records

### 8.1 Logical keys

Features address data by logical key within the active profile. Keys are UTF-8 strings of at most 512 bytes, made of a namespace and a path separated by `/`:

| Namespace | Example logical key | Value |
|-----------|---------------------|-------|
| `importGroups` | `importGroups/2026-10-bank-ing` | import group definition |
| `hiddenLines` | `hiddenLines/8812345` | hide flag and reason for one bank line |
| `ai` | `ai/8812345` | AI classification for one bank line |
| `reminders` | `reminders/ladder` | reminder ladder mapping |
| `prefs` | `prefs/screen/<screenId>` | per-screen preferences |
| `meta` | reserved | never used as a record; profile meta is separate (8.7) |

Features SHOULD store one record per item (one per bank line, one per group) rather than one large map, because last-write-wins works per record and small records conflict less.

### 8.2 Record id

`rid = rid(logical key)` as in section 5.2. Because `NK` is constant per profile, the id of a logical key never changes, including across rotations. The server sees a stable opaque id per logical key.

### 8.3 Plaintext payload and padding

The plaintext JSON payload is:

```json
{
  "k": "hiddenLines/8812345",
  "v": { "hidden": true, "reason": "dubbel" },
  "t": 1793270400123,
  "d": "d_...",
  "h": [42, "<b64u first 16 bytes of the log head hash>"]
}
```

| Field | Meaning |
|-------|---------|
| `k` | logical key. Readers MUST check `rid(k) == id` and reject the record otherwise. |
| `v` | the value, any JSON. `null` in a tombstone. |
| `t` | hybrid clock timestamp of the write (8.6). |
| `d` | device id of the writer. Used as LWW tie-breaker and for display ("laatst gewijzigd op apparaat X"). |
| `h` | the membership log head the writer had verified when writing (log seq and a 16-byte hash prefix). Used for fork detection (9.7). |

`json = utf8(JSON.stringify(payload))`. `len(json)` MUST be at most 65,532 bytes; the store rejects larger values locally with an error the feature can show.

Padded plaintext: `pt = u32(len(json)) || json || zero bytes`, where the total length is the smallest bucket `256 * 2^i` (i = 0..8, so 256 B to 64 KiB) that is at least `len(json) + 4`. Padding hides exact sizes from the server; buckets keep the overhead under a factor two. Readers MUST check that the padding bytes are zero and that the length prefix is in range.

No compression is applied in v1.

### 8.4 Encryption

```
nonce = 12 random bytes
aad   = enc("ebs/v1/rec-aad", profile_id, rid, u32(kv), u64(version), u8(deleted ? 1 : 0))
ct    = AES-GCM-Encrypt(K_rec(kv), nonce, pt, aad)
```

Binding:

- `profile_id`: a record cannot be moved to another profile.
- `rid`: a record cannot be moved to another id (and `k` inside must match).
- `kv`: the server cannot relabel the key version.
- `version`: the server cannot present an old ciphertext under a newer version number.
- `deleted`: the server cannot flip a live record into a tombstone or back.

Wire envelope:

```json
{ "id": "<rid>", "version": 7, "kv": 3, "deleted": false, "nonce": "<b64u 12>", "ct": "<b64u>" }
```

The server adds `change_seq`, `updated_at` (server time) and `updated_by` (device id) on reads.

### 8.5 Versions and compare-and-set

- `version` is a per-record counter. A new record is written with `base_version = 0` and `version = 1`.
- Every upsert or delete writes `version = base_version + 1`. The server accepts the write only if the stored version equals `base_version` (0 means "does not exist"). Otherwise the item is a conflict and the server returns the current envelope.
- A tombstone keeps its version. Re-creating a deleted key is an upsert with `base_version` = tombstone version.
- Rekey writes (section 10.15) keep `version` unchanged, change `kv` and ciphertext, and are accepted only if the stored `(version, kv)` equal the expected values.
- The server MUST reject upserts and deletes whose `kv` is not the profile's current `kv` (`409 stale_key_version`).

### 8.6 Hybrid clock and last-write-wins

Each device keeps `last_t` (the largest `t` it has written or read, persisted in IndexedDB). For a new write: `t = max(now, last_t + 1)` with `now` the offset-corrected time (3.4); then `last_t = t`. On reading a remote record: `last_t = max(last_t, min(remote.t, now + 1 hour))`. A remote `t` more than one hour ahead of `now` is clamped to `now + 1 hour` for comparisons and never advances `last_t` further, so one device with a wrong clock (or a malicious member) cannot push every later write of the profile into the future. Such records are applied normally and the writer is listed under "Klok wijkt af" in the members view.

Conflict resolution when a push returns a conflict for an item, given the local pending write `L` and the server's current record `R` (decrypted):

1. If `R` fails verification, keep `L`, report a security warning, and do not overwrite automatically.
2. Compare `(t, d)` lexicographically (`d` compared as strings). If `L` is greater, re-send `L` with `base_version = R.version`, `version = R.version + 1`, freshly encrypted (new nonce; the AAD contains the new version).
3. Otherwise drop `L` and apply `R` locally.

A namespace MAY register a merge function `(local, remote) -> value` instead of plain LWW (for example to union two sets). The merged value is written as in step 2.

Rollback protection: the client persists, per record id, the highest version it has ever seen (also after the record was deleted locally), and per profile the highest verified log head, `current_kv` and `meta_version`. Each of the following is a rollback; the client then shows "Beveiligingswaarschuwing: de server toont oudere gegevens" naming the profile, stops pushing to that profile, keeps its local state, and resumes only when the server again presents state at least as new as the stored values (or after the user chooses "Opnieuw instellen", which discards the stored values for that profile):

1. a record with a version lower than the highest seen for its id, or the same version with different plaintext (the client stores the SHA-256 of the padded plaintext for the highest version of each id);
2. a log head with a lower seq than the verified head, or the same seq with a different hash;
3. `current_kv` lower than the highest verified `kv`;
4. a meta with `meta_version` lower than the highest seen.

Stale writer check (detects a member who keeps writing with an old key, which happens only if the server withheld a rotation from that member or accepted writes with an old `kv`, see 14.3 T7): when a reader applies a record whose version is newer than any it has seen for that id and whose `kv` is lower than the reader's current `kv`, it looks up the `rotate_key` entry that introduced `kv + 1` (the first version after the record's). If the payload's `h.seq` is lower than that entry's seq and the payload's `t` is later than that entry's `ts` plus 10 minutes, the reader shows "Beveiligingswaarschuwing: <naam> schrijft nog met een oude sleutel" naming the writer device's user (from the log) and offers "Melden aan <naam>". The record is still applied. A rekey write never triggers this check, because it does not change the version.

### 8.7 Profile meta

The profile meta is a single encrypted blob stored on the profile row, not a record, so that `GET /v1/profiles` can return it inline:

```json
{ "administration": "123456", "administration_name": "Voorbeeld BV", "created_by_device": "d_...", "schema": 1 }
```

```
pt    = padded as in 8.3, bucket 256 or 512
aad   = enc("ebs/v1/meta-aad", profile_id, u32(kv), u64(meta_version))
ct    = AES-GCM-Encrypt(K_meta(kv), nonce, pt, aad)
wire  = { "meta_version": 1, "meta_kv": 3, "meta_nonce": "...", "meta_ct": "..." }
```

Updates use compare-and-set on `meta_version` like records. A rotation re-encrypts the meta under the new `kv` in the same request (section 10.14). The administration number of a profile SHOULD never change; if a client finds a different number than its local index, it re-indexes and tells the user.

### 8.8 Tombstones

- Deletes are tombstones: an envelope with `deleted = true` and an encrypted payload with `"v": null`. A tombstone is authenticated like any record, so the server cannot forge deletions.
- The server keeps tombstones for the life of the profile. They are small (one 256-byte bucket plus overhead) and they are the only way a device that was offline for a long time learns about a deletion. Tombstones do not count toward the live record quota; they count toward the byte quota.
- Cursors therefore never expire. A pull from any older cursor returns every change after it, including tombstones.
- A client deletes cached plaintext only because of an authenticated tombstone, a decision by the local user, or its own removal from the profile in the verified log. It never deletes cached plaintext because the server omitted a record, returned an empty result, or reported a profile as deleted or inaccessible; in those cases it keeps the cache and asks the user (10.13 step 2).

---

## 9. Membership log

### 9.1 Entry format

Each profile has one log. An entry on the wire:

```json
{
  "body": {
    "v": 1,
    "profile_id": "p_...",
    "seq": 5,
    "prev": "<b64u 32 bytes, hash of entry seq-1; Z32 for seq 1>",
    "type": "add_device",
    "ts": 1793270400123,
    "author": "d_...",
    "payload": { }
  },
  "sig": "<b64u 64 bytes>"
}
```

That object is shown for readability. On the wire the body travels as its exact canonical string:

```json
{ "body_jcs": "{\"author\":\"d_...\",\"payload\":{...},\"prev\":\"...\",\"profile_id\":\"p_...\",\"seq\":5,\"ts\":1793270400123,\"type\":\"add_device\",\"v\":1}",
  "sig": "<b64u 64 bytes>" }
```

- `sig = ECDSA-Sign(sign_priv_author, enc("ebs/v1/log-sig", body_jcs))`.
- `hash = H(enc("ebs/v1/log-hash", body_jcs))`. The hash covers the body only, not the signature: ECDSA signatures are malleable (3.6), so a hash over the signature bytes would let anyone produce a second valid entry with a different hash. The chain links bodies; each body is still signed.
- Verification uses the exact bytes: the verifier checks `sig` over `utf8(body_jcs)` as received, parses `body_jcs` (rejecting duplicate keys and values outside the JCS profile), recomputes `jcs(parsed)` and requires it to equal `body_jcs` byte for byte. Only then is the parsed body used.
- `ts` is the author's clock, informational only (it is used as a lower bound in the stale writer check of 8.6).
- The server stores `body_jcs` verbatim and returns it unchanged. It also returns `hash` in responses for convenience; clients recompute it.

### 9.2 Device descriptor

Used in payloads:

```json
{ "device_id": "d_...", "user_id": "u_...", "kind": "browser", "sign_pub": "<b64u 65>", "ecdh_pub": "<b64u 65>" }
```

`kind` is `browser` or `recovery`. Names and platforms are not in the log (they are cosmetic and server-provided).

### 9.3 Entry types

| type | payload | Meaning |
|------|---------|---------|
| `genesis` | `{ "owner": "u_...", "owner_name": EncName, "devices": [descriptor, ...], "kv": 1, "dk_commit": "...", "nk_commit": "...", "policy": { "approvers": "members", "auto_approve": false } }` | Creates the profile. `devices` contains the author and, if the owner has one, the owner's recovery device. |
| `add_device` | `{ "device": descriptor, "role": "member" or absent, "user_name": EncName (only with role), "via": "grant" or "self" or "auto" or "recovery", "verified": true or false }` | Adds a device. `role` is present when the device's user is not yet in the profile (a new member); it MUST be `member`, and `user_name` carries the display name the approver saw in the approval card, so that the name becomes member-attested. `verified` records whether the approving human ticked "Ik heb de code vergeleken". |
| `remove_device` | `{ "device_id": "d_..." }` | Removes one device. |
| `remove_user` | `{ "user_id": "u_..." }` | Removes a member and all their devices. Also completes a "leave" that the leaver started server-side. |
| `rotate_key` | `{ "kv": n, "dk_commit": "...", "reason": "removal" or "owner" or "nonce_budget" }` | Introduces `DK_n`. `removal` follows removals in the same request; `owner` is a rotation the owner asked for; `nonce_budget` answers `rotation_recommended` (4.1). |
| `set_policy` | `{ "approvers": "members" or "owner", "auto_approve": true or false }` | Changes the profile policy. |
| `transfer_owner` | `{ "user_id": "u_..." }` | Makes an existing member the owner; the previous owner becomes a member. |
| `set_name` | `{ "user_id": "u_...", "name": EncName }` | Changes the display name of the author's own user in this profile. |

Display names in the log are what the extension shows wherever a name must not be spoofable by the server or another member (approval results, members list, and all of Teamwerk, section 18). They are encrypted, so the log does not hand the server a second, permanent copy of every member's name (which would also survive account deletion in plaintext):

```
K_name = HKDF(NK, Z32, enc("ebs/v1/name", p))                       AES-GCM-256
EncName(user_id, name) = { "nonce": b64u(12 random bytes),
                           "ct": b64u(AES-GCM-Encrypt(K_name, nonce, pad(utf8(NFC(name))),
                                                      enc("ebs/v1/name-aad", p, user_id))) }
pad(x) = u32(len(x)) || x || zero bytes, to a total of 128 bytes, or 512 if it does not fit
```

A name is 1 to 100 code points and follows the display string rules of 3.6. `K_name` derives from NK so names stay readable across rotations. The approver encrypts the name it saw in the approval card (`user_name`); the user replaces it with their own `set_name` on their first sync after approval if it differs, and again whenever they rename themselves in the dashboard. A device without NK (pending) can verify every signature and the structure of `EncName` (base64url, 12-byte nonce, 144 or 528 bytes of ciphertext) but not the name itself. A name that fails to decrypt or to validate does not invalidate the log; it is shown as "Onbekende naam" with a security notice.

### 9.4 State and validation

A client verifying a log maintains:

```
state = {
  owner: user_id,
  users: { user_id: { role: "owner" | "member", name: EncName } },
  devices: { device_id: { user_id, kind, sign_pub, ecdh_pub, added_seq, removed_seq | null, history: [[added_seq, removed_seq]] } },
  kv: integer, dk_commit: { kv: string }, nk_commit: string,
  policy: { approvers, auto_approve },
  pending_rotation: bool,
  head: { seq, hash }
}
```

Entry `e` at log seq `s` is valid against `state` (the state after `s - 1`) if all of these hold, else the whole log is rejected from `s` on and the client shows "Beveiligingswaarschuwing: de ledenlijst van dit profiel is ongeldig" and stops syncing that profile:

1. `body.v == 1`, `body.profile_id` matches, `body.seq == s`, `body.prev == state.head.hash` (or `Z32` for `s = 1`).
2. `sig` verifies under the author's `sign_pub`. For `genesis` the author's key is taken from `payload.devices`. Otherwise the author MUST be an active device in `state` (added and not removed).
3. `body_jcs` passes the exact-bytes check of 9.1; `hash` is computed from it.
4. If `state.pending_rotation` is true, `e` MUST be a `remove_device`, `remove_user` or `rotate_key` by the same author as the removal that set it.
5. Type-specific rules, where `A` is the author device and `U = A.user_id`:

| type | Rule |
|------|------|
| `genesis` | `s == 1`; `payload.owner == U`; `owner_name` structurally valid; every descriptor's `user_id == U`; `kv == 1`; policy values valid. |
| `add_device` via `grant` | Device user `V`. If `V` is not in `users`: `role == "member"` and a structurally valid `user_name` required, and `U` must be the owner, or a member when `policy.approvers == "members"`. If `V` is already in `users`: same approver rule, or `U == V`. |
| `add_device` via `self` | `device.user_id == U`. |
| `add_device` via `auto` | `policy.auto_approve == true`; otherwise as `grant`. |
| `add_device` via `recovery` | `A.kind == "recovery"` and `device.user_id == U`. |
| `add_device` (all) | `device_id` not active. If the id was seen before (it was removed, for example before a re-grant), `sign_pub` and `ecdh_pub` MUST equal the recorded keys; an id is never re-added with other keys. Keys well-formed; at most one active recovery device per user; at most 150 active devices in the profile after the entry. A re-added device gets a new `added_seq`; its earlier interval stays in `history`. |
| `remove_device` | Target active and not `A` itself. `U` is the owner, or `U` is the target's user, or `U` is a member (the server additionally requires a prior server-side revocation, 9.6). At least one active device MUST remain in the profile. Sets `pending_rotation`. |
| `remove_user` | Target in `users`, not the owner, not `U`. `U` is the owner or a member (members: server-side revocation required, 9.6). Removes all the target's devices. Sets `pending_rotation`. |
| (all removals) | The author of a removal MUST NOT be removed by it, directly or through its user, because the same author then generates and learns the next DK. Leaving a profile is therefore a server-side action (`DELETE .../grants/{own user_id}`) that a remaining member completes. |
| `rotate_key` | `payload.kv == state.kv + 1`. If `pending_rotation` is set: `reason == "removal"`, author is the remover; clears `pending_rotation`. Otherwise (standalone rotation): `reason == "owner"` and `U` is the owner, or `reason == "nonce_budget"` and `A` is any active device (the server accepts this only while it reports `rotation_recommended`, 9.6). |
| `set_policy` | `U` is the owner. |
| `transfer_owner` | `U` is the owner; target is a member with at least one active device. |
| `set_name` | `payload.user_id == U`; `name` structurally valid. |

Rationale for members being allowed to remove other members: server-side revocation (by an admin or the owner in the dashboard) is authoritative for access, and the server only accepts a member-authored removal when the server-side grant is already revoked (9.6). Allowing any member device to complete the cryptographic removal means rotation happens as soon as any member is online, instead of waiting for the owner (including removal of the owner's own lost device when the owner has no other device online; the owner's recovery device, if any, keeps the owner represented). A malicious member could only cause a denial of service, which the server-side check blocks anyway. Owner actions (`set_policy`, `transfer_owner`) wait until the owner has an active device again; the owner's new device can be approved by a member (the `add_device` rule for an existing user) or by the owner's recovery kit.

A removal and its `rotate_key` MUST be appended in the same request (the server applies them atomically), so `pending_rotation` is never visible across requests in an honest log.

### 9.5 Wrap authorization

A wrap with `(kv, to, from, at)` is valid only as described in 5.3. In short: the entry at log seq `at` added `to` (or introduced `kv`), and `from` authored it. A malicious server therefore cannot hand a device a key that no member device signed for it.

### 9.6 Server checks on append

The server MUST, before accepting `POST /v1/profiles/{id}/log`:

1. Check `seq == head.seq + 1` for the first entry and continuity for the rest; else `409 log_conflict` with the current head.
2. Verify signatures and hash chaining (it has all public keys). This keeps junk out of the log; clients verify independently.
3. Check server-side authorization:
   - `add_device` for a user `V`: an `active` or `pending` grant for `V` exists, the device belongs to `V`, and the device's `profile_devices` status is `pending`.
   - `remove_device` authored by a member device whose user is neither the owner nor the target device's user: the target's `profile_devices` status MUST already be `revoking` (device revoked server-side) or the target user's grant `revoked`.
   - `remove_user` authored by a member who is not the owner: the target's grant MUST already be `revoked` server-side.
   - `transfer_owner`, `set_policy`, `rotate_key` with `reason: "owner"`: author is the owner.
   - `rotate_key` with `reason: "nonce_budget"`: `rotation_recommended` is true (`writes_at_kv > 2^30`, 12).
   - Re-added device ids: the device is not revoked (`devices.revoked_at` is null) and its `profile_devices` row is `pending` (after a re-grant, 10.9).
4. Check that the side data matches the entries exactly (else `422 log_invalid` with `details: {missing: [...], unexpected: [...]}`):
   - `genesis`: one wrap per genesis device with `kv = 1`, `at = 1`, `from` = author; a meta with `meta_kv = 1`, `meta_version = 1`.
   - each `add_device` at seq `s` for device `D`: exactly one wrap with `to = D`, `kv` = the current kv at `s`, `at = s`, `from` = the entry's author.
   - each `rotate_key` at seq `s` introducing `n`: exactly one wrap with `kv = n`, `at = s`, `from` = the author for every device active after `s`; exactly one history blob with `kv = n`; a meta with `meta_kv = n` and `meta_version` = current plus 1.
   - nothing else: no wraps, history or meta that no entry calls for.
   The server SHOULD also verify each wrap's signature with the stored `sign_pub` of `from`. Clients verify wraps independently (5.3).
5. Apply side effects atomically in one D1 batch: insert entries, insert wraps and history blobs, update meta if given, update `profile_devices`, `profile_members`, `profiles.current_kv`, `rotation_recommended` (cleared by any rotation), head.

### 9.7 Fork detection

A malicious server could show different logs to different members (for example hide a removal from one of them). Clients detect this cheaply:

1. Every record payload carries `h = [log seq, hash prefix]` of the writer's verified head, and every Teamwerk `hello` and `st` frame carries the full head (18.8), so members who are online together compare heads within seconds.
2. When a reader decrypts a record whose `h.seq` is at most its own head seq, the reader MUST check that the hash prefix matches its own log entry at that seq.
3. If `h.seq` is greater than its own head, the reader fetches the log; if the server cannot provide entries up to `h.seq` that match the prefix, the reader shows a security warning and stops writing to the profile.
4. On mismatch the client shows "Beveiligingswaarschuwing: de server toont verschillende ledenlijsten" and stops syncing the profile until a user resolves it.

This detects a fork between any two members as soon as one reads a record the other wrote after the fork point. It does not detect a fork between members who never write.

### 9.8 Limits

- At most 10,000 entries per log (enough for decades of normal use). A log of a few hundred entries is verified from genesis in milliseconds; clients cache verified state and verify only new entries afterwards.
- Append rate limits: 30 appends per minute per profile, 10 per minute per device, and 500 entries per day per profile (11.4). A request carries at most 50 entries, 160 wraps and 512 KiB of body.
- At most 150 active devices per profile, including recovery devices, so that one rotation (one wrap per active device) always fits in one request.
- At the 10,000-entry cap the server keeps accepting only what revocation needs: a batch of removals with their `rotate_key (reason: removal)`, up to a hard limit of 10,500 entries. Everything else (`add_device`, `set_policy`, `set_name`, `transfer_owner`, standalone rotations) is refused with `422 quota_exceeded` and `details.reason = "log_full"`. Record sync, Teamwerk, exports and reading the log keep working. The extension then offers "Profiel opnieuw opbouwen": it creates a new profile for the same administration, copies all live records into it, and the owner shares it again with the same users.

---

## 10. Flows

Every flow is written as numbered steps. "Client" means the extension service worker unless an extension page is named. "Server" means the Worker. Error handling not listed explicitly follows section 11.3.

### 10.1 Instance setup and admin bootstrap

1. The self-hoster clicks the deploy button. Wrangler creates the Worker, the D1 database (with the EU location hint where the hoster is in the EU) and applies migrations (`migrations/0001_init.sql`, section 12).
2. The self-hoster sets configuration (section 11.10), at minimum: `ISSUER` (the public origin, for example `https://sync.example.nl`), `RP_ID` (the host name, for example `sync.example.nl`), `ADMIN_EMAILS` (comma-separated), `ALLOWED_EXTENSION_IDS` (comma-separated; the Chrome Web Store id of EB Sessions is the default), the email provider credentials as Worker secrets, and `REGISTRATION` (`closed` default, or `open`).
3. The self-hoster opens the dashboard and requests an email login code for an address in `ADMIN_EMAILS`. On first login the server creates the user with `is_admin = 1`. Users whose verified email is in `ADMIN_EMAILS` are admins; removing an address from the list removes the flag at their next login.
4. The dashboard asks the admin to register a passkey (10.3, step R1). Until a passkey exists, a banner says that email login alone is weaker.

### 10.2 Account creation by an admin

1. The admin opens "Gebruikers" in the dashboard, enters email and display name, and chooses "Uitnodiging per e-mail" or "Link kopiëren". `POST /v1/admin/users`.
2. The server creates a `users` row with `status = 'invited'` and a set-up token (32 random bytes, stored as `H(token)`, valid 72 hours, single use). The link is `https://<host>/setup#t=<b64u token>`. The token is in the URL fragment so it never reaches server logs or `Referer` headers.
3. If email was chosen, the server sends the link. Otherwise it returns the link once in the response and the admin delivers it.
4. The invitee opens the link. The dashboard script reads the fragment, calls `POST /v1/auth/setup {token}`, and gets a session (`status` becomes `active`, `email_verified_at` is set because the link proves mailbox control).
5. The dashboard asks the invitee to register a passkey and then shows "Verbind EB Sessions": open the extension and click "Verbinden".
6. Optionally in the same dialog, the admin grants profiles (10.9). Grants for a user who has no device yet stay pending until the user connects a device and a member approves.

If `REGISTRATION = open`, anyone can create an account by requesting an email code for a new address (10.3, step E1 with `purpose = signup`). The account starts with no grants.

### 10.3 Dashboard login, passkeys and re-authentication

Passkey registration (requires a session):

- R1. `POST /v1/auth/webauthn/register/options` returns `PublicKeyCredentialCreationOptions` with: `rp = {id: RP_ID, name: instance name}`, `user = {id: random 16-byte user handle stored per user, name: email, displayName: name}`, `challenge` (32 random bytes, stored server-side, valid 5 minutes, single use), `pubKeyCredParams = [ES256 (-7), EdDSA (-8), RS256 (-257)]`, `authenticatorSelection = {residentKey: "required", userVerification: "required"}`, `attestation = "none"`, `excludeCredentials` = existing credentials.
- R2. The browser runs `navigator.credentials.create`. The dashboard posts the result to `/v1/auth/webauthn/register/verify`.
- R3. The server verifies per WebAuthn Level 3 section 7.1: type, challenge, origin equals `ISSUER`, `rpIdHash`, UP and UV flags set, algorithm allowed. It stores credential id, COSE public key, sign count, transports, backup flags, a user-chosen name.

Passkey login:

- L1. `POST /v1/auth/webauthn/login/options` returns `PublicKeyCredentialRequestOptions` with a fresh challenge, `rpId`, `userVerification: "required"`, and empty `allowCredentials` (discoverable credentials, no username needed, no account enumeration).
- L2. The browser runs `navigator.credentials.get`; the dashboard posts to `/v1/auth/webauthn/login/verify`.
- L3. The server finds the credential by id, verifies the assertion (WebAuthn section 7.2), requires UV, checks the sign counter (if both stored and received counters are non-zero and the received one is not greater, it rejects the login and records `auth.passkey_counter_regression` in the audit log), updates `last_used_at`, and creates a session.

Email login (fallback):

- E1. `POST /v1/auth/email/start {email, purpose: "login" | "signup"}` always answers `202 {login_request_id}` (no account enumeration). If the account exists and is active (or `signup` is allowed), the server sends an email with an 8-digit code and a link `https://<host>/login#r=<login_request_id>&c=<code>`. The code is valid 15 minutes, at most 5 verification attempts, stored as `H(enc("ebs/v1/email-code", login_request_id, code))`.
- E2. The user types the code (works inside the extension's auth window, which cannot receive a link click) or clicks the link (the dashboard script reads the fragment). `POST /v1/auth/email/verify {login_request_id, code}` creates a session.
- E3. A user MAY disable email login once at least one passkey exists (`PATCH /v1/account {email_login: false}`). Admins SHOULD do this; the dashboard recommends it.

Sessions:

- Cookie `__Host-ebs_session`: 32 random bytes, `Secure; HttpOnly; SameSite=Strict; Path=/`. Stored as `H(value)`.
- Idle timeout 30 minutes, absolute lifetime 12 hours.
- Re-authentication: sensitive actions (approve a device connection, revoke a device, delete a profile, delete the account, export, change admin flags, disable email login) require a user-verified authentication within the last 5 minutes. `POST /v1/auth/reauth/options` and `/verify` (a passkey assertion, or an email code if the user has no passkey) set `elevated_until = now + 5 min`. Otherwise these endpoints answer `403 reauth_required`.
- Logout: `POST /v1/auth/logout` deletes the session.

### 10.4 Connecting the extension (primary: OAuth 2.0 authorization code with PKCE)

The "Verbinden" button lives on the extension options page, opened as a full tab. The popup's "Verbinden" button opens the options page with `#connect`. Reason: the popup closes when the auth window takes focus, which would kill the flow's JavaScript.

1. The user enters the server URL (pre-filled with the hosted instance, if any). The client requires `https:` (or `http://localhost` and `http://127.0.0.1` in development builds only).
2. In the same click handler (a user gesture is required), the options page calls `chrome.permissions.request({permissions: ["identity"], origins: [origin + "/*"]})`. If refused, the flow stops with an explanation. The pairing code flow (10.5) requests only the host permission.
3. The options page fetches `GET <origin>/v1/meta` and checks `protocol_versions` contains 1 and `issuer == origin`.
4. If the device has no key pairs for this server, the client generates them (6.4). It computes `device_jkt` and the device code (5.6) and shows the device code on the options page.
5. The client creates `code_verifier` = b64u(32 random bytes) (43 characters), `code_challenge = b64u(H(ascii(code_verifier)))`, `state` = b64u(16 random bytes), and stores `{state, code_verifier, origin, started_at}` in `chrome.storage.session`.
6. The client calls `chrome.identity.launchWebAuthFlow({url, interactive: true})` with
   `url = <origin>/oauth/authorize?response_type=code&client_id=<chrome.runtime.id>&redirect_uri=<chrome.identity.getRedirectURL("oauth")>&code_challenge=<..>&code_challenge_method=S256&state=<..>&scope=device&device_jkt=<..>&device_name=<urlencoded, max 64 chars>`.
   The redirect URI has the form `https://<extension-id>.chromiumapp.org/oauth`.
7. The server validates, before rendering anything else:
   - `client_id` is in `ALLOWED_EXTENSION_IDS`;
   - `redirect_uri` is exactly `https://<client_id>.chromiumapp.org/oauth` (byte-for-byte string comparison, no wildcard, no prefix match, no extra path or query);
   - `response_type == "code"`, `code_challenge_method == "S256"`, `code_challenge` is 43 base64url characters, `state` is 16 to 128 characters, `device_jkt` is 43 base64url characters.
   If `client_id` or `redirect_uri` fail, the server shows an error page and MUST NOT redirect. Other errors redirect with `error=invalid_request&state=...&iss=...`.
8. The page asks the user to log in: passkey (10.3 L1 to L3) or email code (E1, E2, typing the code). The auth window MUST NOT depend on an existing dashboard session being visible in it.
9. The consent page shows: account email, device name, the device code computed from `device_jkt` (first 100 bits, section 5.6), the extension id, and the text "Koppel dit apparaat alleen als je dit zelf net in EB Sessions hebt gestart en de apparaatcode overeenkomt." Buttons "Apparaat koppelen" and "Annuleren". Approval requires an authentication with user verification within the last 5 minutes (the login of step 8 counts).
10. On approval (`POST /oauth/authorize/decision`, a same-origin form submission with the `csrf` field, 11.5), the server creates an authorization code: 32 random bytes, stored as `H(code)` with `client_id`, `redirect_uri`, `code_challenge`, `device_jkt`, `user_id`, `expires_at = now + 60 s`, `used_at = null`. It answers with a redirect to `redirect_uri?code=<b64u>&state=<state>&iss=<urlencoded ISSUER>` (RFC 9207 `iss` against mix-up).
11. `launchWebAuthFlow` resolves with the final URL. The client parses it, requires `state` to equal the stored value and `iss` to equal the origin, then deletes the stored state. On `error`, it shows the reason. If `launchWebAuthFlow` rejects (the user closed the window, the page could not load, or the browser does not support the API), the options page switches straight to the pairing code flow (10.5) with "Lukt inloggen in het venster niet? Koppel met een code." The same flow is always offered as a secondary link "Koppelen met een code" under the "Verbinden" button.
12. The client calls `POST /oauth/token` (11.5) with the code, `code_verifier`, `client_id`, `redirect_uri`, the device public keys and a `device_proof` signature.
13. The server, in one D1 batch: marks the code used with `UPDATE ... SET used_at = now WHERE code_hash = ? AND used_at IS NULL AND expires_at > now`; if no row changed and the code exists, it is a replay, so the server revokes the device created from that code (if any) and answers `invalid_grant`. It then checks PKCE (`b64u(H(code_verifier)) == code_challenge`), `client_id` and `redirect_uri` equality, `device_jkt == b64u(H(enc("ebs/v1/device-code", sign_pub, ecdh_pub)))`, and the proof signature.
14. If an earlier, not revoked device of the same user has the same `device_jkt` (the device reconnects after its token expired), the server reissues a token for that `device_id`. Otherwise it creates a new device. It creates `profile_devices` rows with `status = 'pending'` for every profile where the user has an `active` or `pending` grant. It returns the device token.
15. The client stores `device_id` and the token in IndexedDB (6.1), shows "Verbonden als <email>" and runs a full sync (10.13). Profiles that need approval appear as pending.

### 10.5 Connecting the extension (fallback: pairing code)

The automatic fallback when `launchWebAuthFlow` fails or is closed (10.4 step 11), and a secondary option the user can pick directly (for example on a Chromium fork, or when passkeys do not work inside the auth window). Modeled on the OAuth 2.0 device authorization grant (RFC 8628), with renamed fields to avoid confusion with the device code fingerprint.

1. Steps 1 to 4 of 10.4.
2. `POST /oauth/pairing {client_id, device_jkt, device_name}` returns `{pairing_secret, user_code, verification_uri, expires_in: 600, interval: 5}`. `user_code` is 8 characters from `BCDFGHJKLMNPQRSTVWXZ` shown as `XXXX-XXXX`. `pairing_secret` is 32 random bytes, stored as a hash.
3. The options page shows the user code and the device code and opens `verification_uri` (`https://<host>/koppelen`) in a new tab. The user code is not put in the URL, so a phishing link cannot pre-fill someone else's code.
4. The user logs in, types the user code, sees device name and device code, and approves (user verification within 5 minutes). Wrong user codes count against a limit of 5 per session per 10 minutes.
5. While the options page is open, the client calls `POST /oauth/token {grant_type: "urn:ebs:params:oauth:grant-type:pairing", pairing_secret, client_id, device, device_proof}` every `interval` seconds. Answers: `400 authorization_pending`, `400 slow_down` (add 5 s to the interval), `400 expired_token`, `400 access_denied`, or `200` with the token. The client stops after `expires_in` or when the page closes. This bounded wait is the only polling in the protocol.
6. Steps 14 and 15 of 10.4.

Release testing MUST cover passkeys and email codes inside the `launchWebAuthFlow` window on macOS, Windows and ChromeOS, and the switch to this fallback when the window is closed or fails.

### 10.6 Device token format, rotation and revocation

- Format: `ebs_dt_` followed by b64u(32 random bytes). Opaque. The prefix allows secret scanners to find leaked tokens.
- At rest: the server stores `H(token)` only. Lookup is by hash; constant-time comparison is not needed because the hash is the lookup key.
- Every device request also carries an ECDSA request signature (11.2). A token without the device private key is useless.
- Rotation: when the token is older than 30 days, the client calls `POST /oauth/token {grant_type: "urn:ebs:params:oauth:grant-type:rotate"}` authenticated with the current token and signature. The server issues a new token and keeps the previous hash valid for 120 seconds (`prev_token_hash`, `prev_token_expires_at`) so in-flight requests do not fail. The client stores the new token before using it.
- Expiry: a token unused for 180 days expires. The device can reconnect with the same keys (10.4 step 14), which keeps its profile memberships.
- Revocation:
  - from the extension, "Ontkoppelen": `POST /oauth/revoke {token}` (RFC 7009 semantics: always `200`). This revokes the device.
  - from the dashboard: `DELETE /v1/devices/{device_id}` (session, re-auth). Admins can revoke any device.
  - Revoking a device sets `devices.revoked_at`, deletes its token hashes, and marks its `profile_devices` rows `revoking`. The server stops serving profile data to it immediately. The cryptographic removal and rotation follow at the next sync of an eligible member device (10.14).
- One device has exactly one valid token (plus the 120-second grace token). Revoking the token and revoking the device are the same action.

### 10.7 Profile creation

Triggered by "Nieuw profiel" in the popup or navbar menu, or automatically per 7.4 rule 3.

1. The client detects the administration number of the current tab (reported by the content script, 15.4) and asks the user to confirm "Profiel aanmaken voor administratie <nummer> (<naam>)?" when the creation is automatic for the first time.
2. Generate `profile_id`, `NK`, `DK_1`.
3. Include the user's recovery device if it is trusted (10.16, "Trusting and adding a recovery device automatically").
4. Build the `genesis` entry: `owner = my user_id`, `owner_name = EncName(my user_id, my display name)` (9.3), devices = this device (plus the recovery device), `kv = 1`, `dk_commit(1)`, `nk_commit`, default policy. Sign it.
5. Build wraps for every genesis device with `at = 1`.
6. Build the meta (8.7) with the administration number and name, `meta_version = 1`.
7. `POST /v1/profiles {profile_id, label: "Mijn profiel" or the user's choice, genesis, wraps, meta}`.
8. The server checks the limit of owned profiles, uniqueness of `profile_id`, the genesis signature and that all genesis devices belong to the caller. It creates the profile, an `active` grant with role `owner`, `profile_devices` rows, wraps and the log entry, all in one batch.
9. The client adds the profile to its administration index, makes it active for this administration, and moves existing local data for that administration into it if the user agrees ("Bestaande gegevens van dit apparaat meenemen?"), by enqueueing every local item as a write.
10. If the owner has other devices, they appear as pending in this profile; the owner approves them from this device (10.10) or they are approved by self-approval when they come online with another approved device available.

### 10.8 Administration index and profile switch

1. During sync step 2 (10.13), the client receives all accessible profiles with `meta_version`, `meta_kv`, `meta_nonce`, `meta_ct`.
2. For each active profile whose `meta_version` differs from the cached one, the client decrypts the meta (keys from 5.2) and updates the index `administration -> [profile_id]`.
3. When a content script reports an administration (on navigation), the service worker answers with `{profiles: [{profile_id, label, owner_name, is_owner}], active_profile_id, pending: [{label, owner_name}]}` for that administration. Labels and names are not secret; no keys, ids of other administrations or data leave the service worker.
4. The navbar menu and the popup render the switch when more than one profile is listed. Selecting one sends `{type: "profile:select", profile_id}`. The service worker checks that the profile is in the index for the sender's administration, stores it in `activeProfileByAdministration`, and notifies the tab to reload feature state.

### 10.9 Sharing and pending grants (new member)

Grant creation:

1. An admin in the dashboard ("Toegang", choose user and profile) calls `POST /v1/admin/grants {user_id, profile_id}`. Or the owner, in the extension ("Delen" in the profile menu) or the dashboard, calls `POST /v1/profiles/{id}/grants {email}`. If no account exists for that email: admins get an account created (10.2); owners get `404 user_not_found` unless the instance setting `OWNERS_CAN_INVITE = true`, in which case the server creates an invited account and sends the set-up link.
2. The server creates `profile_members` with `role = 'member'`, `status = 'pending'`, `granted_by`, and `profile_devices` rows with `status = 'pending'` for each active device of the grantee. Devices the grantee connects later get rows too.
3. The server records audit event `grant.created` and, if email notifications are on, emails the grantee ("Je hebt toegang gekregen tot <profiel>. Open EB Sessions en verbind het met <host>.") and the approvers ("<naam> wil toegang tot <profiel>. Open EB Sessions om dit toe te staan of te weigeren."). The emails contain no action links.

What the grantee sees while pending:

4. In the popup and in the navbar menu: "Wacht op goedkeuring door <naam eigenaar> voor <profiel>". If the policy is `approvers: members`, the text adds "of door een ander lid". Below: "Jouw apparaatcode: K7QM 2XPA 9RTD W4HE 8NBC. Als iemand vraagt om de code te vergelijken, lees deze voor." Pending profiles are listed whatever administration is open, because the grantee cannot know the administration yet.

What the approver sees:

5. Any device allowed to approve (9.4) learns about pending requests in sync step 4 (10.13, `GET /v1/approvals`). The extension sets the action badge to the number of requests and shows in the popup and the navbar menu a card: "<naam> wil toegang tot <profiel>", with email, device name and platform, "toegang gegeven door <naam>", the date, and the device code computed locally from the public keys in the request. Text: "De naam en het e-mailadres komen van de server. Alleen de apparaatcode bewijst dat dit het apparaat van <naam> is." A checkbox "Ik heb de code vergeleken" (not pre-ticked) and buttons "Toestaan" and "Weigeren".
6. On "Toestaan":
   1. Sync the log of the profile (fetch new entries, verify).
   2. Re-fetch the request and check that the device is still pending and that its public keys are those shown (the device code on screen must be the one computed from the keys that will be signed).
   3. For each pending device of that user in that profile (normally one), build an `add_device` entry: descriptor, `role: "member"` and `user_name = EncName(user_id, the name shown in the card)` (9.3) on the first entry if the user is new, `via: "grant"`, `verified` from the checkbox. Consecutive log seqs.
   4. Unwrap this device's wrap for the current `kv` with `extractable` raw bytes (decrypt to `NK || DK`), wrap for each new device with `at` = its entry's seq, then zero the plaintext.
   5. `POST /v1/profiles/{id}/log {entries, wraps}`.
   6. On `409 log_conflict`, repeat from step 6.1 once. If the request is no longer pending (someone else approved), show "Al goedgekeurd door <naam>". A second conflict stops with an error.
7. The server validates (9.6), stores, sets the grant `active` and the devices `active`, and records `grant.approved` with `verified`.
8. On "Weigeren": `POST /v1/approvals/deny {profile_id, user_id}`. The grant becomes `denied`; the grantee sees "Toegang geweigerd". Only an admin or the owner can re-open it (create a new grant). A mismatch reported via "Codes komen niet overeen" also denies, records `grant.code_mismatch` as a security event, and shows the approver a warning that the server may be substituting keys.

The grantee after approval:

9. At its next sync (the popup opening also triggers one), the grantee's device sees `my_status = active`, fetches and verifies the log from genesis, verifies its wrap (5.3), decrypts the meta, indexes the administration, and pulls records.
10. It shows once: "Toegang tot <profiel> goedgekeurd door <naam> (apparaat <naam>, code XXXX ...). Vergelijk deze code met <naam> als je zeker wilt weten dat dit profiel echt van hen is." This lets the grantee detect a fake profile set up by a malicious server.
11. If the name the approver encrypted into `user_name` differs from the grantee's own display name, the grantee's client appends `set_name` (9.3).

Re-grants and status transitions:

`profile_members.status`:

| From | Event | To |
|------|-------|----|
| (none) | grant created by an admin or the owner | `pending` |
| `pending` | first `add_device` for the user accepted | `active` |
| `pending` | "Weigeren" or "Codes komen niet overeen" | `denied` |
| `pending` | grant revoked before approval | `revoked` (no log entry needed; the user was never in the log) |
| `active` | grant revoked (admin, owner, the user leaving, account deletion) | `revoked`; the user's devices become `revoking` until a member appends `remove_user` |
| `denied`, `revoked` | new grant by an admin or the owner (a re-grant) | `pending`; `granted_by` and `granted_at` are updated in the same row |

`profile_devices.status`:

| From | Event | To |
|------|-------|----|
| (none) | grant created, or the user connects a device while a grant is `pending` or `active` | `pending` |
| `pending` | `add_device` accepted | `active` |
| `pending` | request denied, or grant revoked before approval | `denied` or `removed` |
| `active` | device revoked (10.6) or grant revoked | `revoking` |
| `revoking`, `active` | `remove_device` or `remove_user` accepted | `removed` |
| `removed`, `denied` | re-grant of the user, or "Opnieuw toegang vragen" from that device while the grant is `active` (`POST /v1/profiles/{id}/access-request`) | `pending`, only if the device itself is not revoked (`devices.revoked_at` is null) |

A re-added device keeps its `device_id` and keys (9.4 allows re-adding a removed id with identical keys). A re-granted user regains access to the whole profile, including records written while they were removed: access is to the profile's data, not to a time window. Revoked devices never return; they reconnect as new devices.

### 10.10 New device of an existing member (self-approval)

1. The user connects a new device (10.4). The server creates pending `profile_devices` rows in every profile where the user has an active grant.
2. Any other active device of the same user sees, in sync step 4 (10.13), a request of kind `own_device`: "Je nieuwe apparaat '<naam>' wil toegang tot <n> profielen", with the device code. Because both devices are usually in front of the user, the dialog asks explicitly: "Staat dezelfde code op je nieuwe apparaat?" The new device's options page shows its code prominently while it waits.
3. "Toestaan" appends, per profile, an `add_device` entry with `via: "self"` and wraps, exactly as 10.9 step 6, one request per profile, sequentially.
4. If the user has no other device, other members can approve (the request also appears for them, per the policy), or the user uses the recovery kit (10.16).

### 10.11 Automatic approval (optional, per profile)

1. Only the owner can enable it: profile menu, "Automatisch goedkeuren". The dialog states: "Als dit aan staat, krijgt elk apparaat dat de server als lid aanmeldt automatisch toegang. Je vertrouwt dan de server en iedere beheerder volledig met de gegevens van dit profiel." The owner must tick an acknowledgement.
2. The client appends `set_policy {approvers, auto_approve: true}`.
3. Any approver-eligible member device that sees pending requests for that profile approves them without asking (10.9 step 6 with `via: "auto"`, `verified: false`) and shows a notification "<naam> heeft automatisch toegang gekregen tot <profiel>".
4. Disabling appends `set_policy` with `auto_approve: false`. Devices added via `auto` stay members; the members list marks them "automatisch toegevoegd" so the owner can review and remove them.

### 10.12 Device code UX requirements

These are normative for the client:

1. The device code MUST be computed locally from the public keys that will be (or were) signed into the log, never taken from a server-provided string.
2. It MUST be shown in a monospace font, 5 groups of 4 characters.
3. It MUST be shown: on the requesting device while it waits for approval; in every approval card; next to every device in the profile members list; and under "Mijn apparaat" in the options page.
4. The approval card MUST state that name and email come from the server and only the code proves the device.
5. "Toestaan" MUST be possible in one click without ticking the comparison box (product requirement). The log records `verified: false` in that case, and the members list shows "code niet vergeleken" for that device.
6. The members list offers "Code vergelijken" for any device at any time. Confirming stores local verification state on that device only.
7. A "Codes komen niet overeen" action MUST exist in the approval card and deny the request (10.9 step 8).

### 10.13 Sync

Triggers (no polling loops):

| Trigger | Scope | Throttle |
|---------|-------|----------|
| Content script reports a screen open in e-Boekhouden | active profile of that administration | skipped if that profile synced successfully less than 60 s ago |
| Local change through the store | the changed profile | debounce 2 s after the last write, at most 10 s after the first unsynced write |
| "Nu synchroniseren" in popup or navbar menu | all profiles | none |
| Popup opened | profile list and approvals only (steps 1, 2 and 4) | 30 s |
| `chrome.runtime.onStartup`, after connecting, after approval | all profiles | none |
| Retry after a failed sync or a non-empty outbox | failed profiles | one-shot `chrome.alarms` with exponential backoff 30 s, 1, 2, 4, 8, 16, 30 min (cap); cleared on success. Not a periodic poll. Chrome 120 and later accept a 30-second minimum delay; Chrome 116 to 119 clamp alarms to at least 1 minute, so the first step is 1 minute there. |

Algorithm for one sync run:

Debounce timers use `setTimeout` in the service worker. This is safe: every store message from a content script resets the worker's idle timer, a page navigation within e-Boekhouden sends a new screen-open message within seconds, and the outbox is persisted, so a worker that is stopped before a timer fires flushes the outbox when it next starts (`onStartup`, the next message, or the retry alarm).

1. Acquire `navigator.locks.request("ebs-sync")` for the profile list step, then per profile `ebs-sync:<profile_id>`. If `navigator.onLine` is false, schedule a retry and stop.
2. `GET /v1/profiles`. Update the local list. For profiles that disappeared or return `profile_deleted` or `access_revoked`: stop syncing them, keep the local copy, and show "Profiel <naam> is niet meer beschikbaar. Lokale kopie exporteren of verwijderen?".
3. For each active profile, in order of use:
   1. If the server head differs from the local head: `GET /v1/profiles/{id}/log?after=<local head seq>`; verify (9.4); if verification fails, stop this profile with a security warning. If this device is no longer active in the log, delete keys and cached wraps for the profile and treat it as in step 2.
   2. If `current_kv` changed or a wrap is missing: `GET /v1/profiles/{id}/keys`; verify wrap and history (5.3, 5.4).
   3. Meta: step 2 of 10.8.
   4. Pull: `GET /v1/profiles/{id}/records?since=<cursor>&limit=500` until `has_more` is false. For each envelope: decrypt, verify `rid(k) == id`, padding, version not lower than seen (8.6), log head gossip (9.7). If no local pending write exists for the id, apply it to the cache. If one exists and the remote version is not lower than its base, resolve with LWW now (8.6) and rebase the pending write. Store the new cursor after each page.
   5. Writer check before pushing (the stale writer heuristic, see 8.6 and 14.3 T7). Do not push, and show "Beveiligingswaarschuwing: synchronisatie van <profiel> is gestopt omdat de ledenlijst niet bijgewerkt kan worden", if any of these happened in this run or since the last successful verification:
      - a record arrived with a `kv` higher than this device's current `kv`, or a profile summary reported a higher `current_kv`, and the log or keys up to it could not be fetched and verified;
      - a record payload or a Teamwerk `hello` or `st` frame (18.8) carried a log head with a higher seq than the verified head, and the log up to it could not be fetched and verified;
      - a rollback (8.6) or fork (9.7) was detected.
      In addition, when the profile has other active members and this device has written records but has seen no record and no Teamwerk frame from any other device for 14 days, the extension shows a soft notice: "Je ziet al 14 dagen geen wijzigingen van collega's in <profiel>. Vergelijk de ledenlijstcode met een collega." The members view shows the ledenlijstcode, the first 8 Crockford base32 characters of the verified head hash plus its seq, so two members can compare their logs out of band.
   6. Push: send the outbox in batches of at most 200 writes and 1 MiB: `POST /v1/profiles/{id}/records:put`. Apply per-item results: `ok` removes the item from the outbox and updates the cached version; `conflict` resolves per 8.6 and re-queues if needed. Stop after 3 rounds per run to avoid ping-pong; the rest goes to the next run.
   7. If the profile list reported `pending_removals` and this device may sign them (9.4): run 10.14 automatically and notify "Apparaat <naam> is verwijderd uit <profiel>; de sleutel is vernieuwd."
   8. If the user has a trusted recovery device (10.16) that is not active in this profile, and this device is active: add it (`add_device` with `via: "self"` and a wrap).
   9. If `rekey_pending` is true: run up to 5 batches of 10.15.
4. If `approvals_pending > 0` in the profile list: `GET /v1/approvals` and update badge and cards (no automatic action unless 10.11).
5. Rotate the token if due (10.6).
6. Store last-sync timestamps; release locks.

Offline behaviour: all reads come from the local cache; all writes go to the cache and the outbox immediately and resolve the store promise. The UI shows "Niet gesynchroniseerd (<n> wijzigingen wachten)" when the outbox is non-empty for more than a minute. Server `Retry-After` values are respected.

### 10.14 Removal and key rotation

Triggers: a member removes a device or user in the extension; a server-side revocation shows up as `pending_removals` (device revoked in the dashboard, grant revoked by admin or owner, account deleted); a member leaves; a recovery kit is replaced; `rotation_recommended`; the owner chooses "Sleutel vernieuwen".

Steps on the acting device:

1. Sync the log (10.13 step 3.1).
2. `kv_new = kv + 1`, `DK_new` = 32 random bytes.
3. Entries: the removals (`remove_device` and/or `remove_user`), then `rotate_key {kv: kv_new, dk_commit: dk_commit(kv_new), reason: "removal"}`. Without a removal, only `rotate_key`: with `reason: "nonce_budget"` when the server reports `rotation_recommended` (any active device), or `reason: "owner"` when the owner chooses "Sleutel vernieuwen" (owner devices only).
4. Wraps of `NK || DK_new` for every device that is active after the removals, including this device and recovery devices, all with `at` = the `rotate_key` seq.
5. History blob `DK_old` under `K_hist(kv_new)` (5.4).
6. Meta re-encrypted under `K_meta(kv_new)` with `meta_version + 1`.
7. `POST /v1/profiles/{id}/log {entries, wraps, history, meta}`.
8. The server applies atomically: entries; wraps; history; meta; `profile_devices` of removed devices set to `removed`; all wraps addressed to removed devices deleted (every kv); grants of removed users set to `revoked`; `current_kv = kv_new`; `rekey_pending = true` if any record has `kv < kv_new`.
9. On `409 log_conflict`: refetch and re-evaluate. If another device already performed the same removal and rotation, stop. Otherwise retry once; a second failure stops and reports.

From step 8 on, the server rejects upserts with the old `kv` (`409 stale_key_version`); clients that get this error sync the log and keys and re-encrypt their pending writes.

What rotation achieves and does not: the removed party cannot decrypt anything written after the rotation, even with a copy of the database. Everything it could read before (its local cache, old ciphertext it downloaded, `DK_old`) stays readable to it. Re-encryption (10.15) limits what a later database leak combined with `DK_old` exposes; it cannot take back what was already seen.

### 10.15 Lazy re-encryption

Goal: move records with `kv < current_kv` to `current_kv` without a request storm. Any active member device may do it.

1. Precondition: `rekey_pending` in the profile list.
2. `POST /v1/profiles/{id}/rekey/lease {kv: current_kv}`. Answers: `200 {lease_id, expires_at, remaining}` (lease of 60 s, one holder per profile), `409 lease_held {expires_at}` (skip; another device is working), `204` (nothing left).
3. The client keeps a pass cursor `after` (empty at the start of a pass, stored in IndexedDB with the `kv` it belongs to, so a pass can resume in the next sync run). Repeat at most 5 times per sync run:
   1. `GET /v1/profiles/{id}/rekey/batch?lease_id=<..>&after=<cursor>&limit=200` returns up to 200 envelopes with `kv < current_kv` ordered by `(kv, id)` and strictly after the cursor, plus `next_after` (the cursor of the last returned row, or null at the end of the pass). The cursor makes progress even past records that cannot be rekeyed (they stay at the old `kv` and would otherwise be returned again forever).
   2. For each envelope: obtain `DK_old` through the history chain, decrypt and verify as in pull, then encrypt the identical padded plaintext under `K_rec(current_kv)` with a new nonce and the same `version` and `deleted` (the AAD changes only in `kv`).
   3. `POST /v1/profiles/{id}/records:put {lease_id, writes: [{op: "rekey", id, version, from_kv, kv, nonce, ct}]}`. The server applies each item only if the stored `(version, kv)` equals `(version, from_kv)`; otherwise the item result is `skipped` (a newer write at the current kv already replaced it). Rekey writes do not change `change_seq` or `updated_at`, so other devices do not re-download unchanged content. Each rekey batch renews the lease.
   4. Wait at least 1 s before the next batch. On `429`, stop and continue at the next sync run.
4. Records that fail to decrypt are skipped and counted. They keep old keys alive. The extension reports them to the owner ("<n> records konden niet worden omgezet") with the action "Verwijderen", which writes authenticated tombstones for them at the current `kv` (an upsert with `op: "delete"` and `base_version` = the stored version needs no decryption of the old content).
5. When `next_after` is null, the client calls `POST /v1/profiles/{id}/rekey/complete {lease_id, kv}`. The server counts records with `kv < current_kv`. If the count is 0, it sets `rekey_pending = false`, deletes history blobs and wraps for versions below `current_kv`, releases the lease and answers `200 {remaining: 0, cleared: true}`. Otherwise it answers `200 {remaining: n, cleared: false}` and keeps the old keys; the client starts a new pass in a later sync run only if the count went down since the previous pass, so undecryptable records do not cause endless passes. Clients drop cached keys for deleted versions when they see `rekey_pending = false`.

Properties: idempotent (compare-and-set on `(version, kv)`, same version number), resumable (progress is server state), single worker (lease), crash-safe (lease expiry), bounded load (at most 30 batches per minute per profile enforced by the server, 5 batches per sync run by the client).

### 10.16 Recovery kit

Creating a kit ("Herstelsleutel maken" in the options page; one kit per user):

1. Generate `rk`, `salt`, and the recovery device key pairs (extractable, in memory only).
2. `POST /v1/devices/recovery {sign_pub, ecdh_pub}` (device token and signature). The server creates a device with `kind = 'recovery'` for the user, without a token, and pending `profile_devices` rows for the user's profiles. If an active recovery device exists, the server keeps it until step 6.
3. Build the blob (5.5: encrypted private and public keys, `test_sig`, `attest`) and `PUT /v1/account/recovery-kit`.
4. For each profile the user can access: append `add_device {device: recovery descriptor, via: "self", verified: true}` with a wrap, one request per profile, sequentially.
5. Show the kit on a printable extension page: instance URL, account email, recovery key (8 groups of 4), recovery device code, date, and instructions. The user confirms by typing the last group. The key is never sent anywhere and is dropped from memory after printing; the private keys are dropped after step 4.
6. If an older recovery device existed: remove it from every profile (10.14, removal plus rotation) and `DELETE /v1/account/recovery-kit/{old_recovery_device_id}`.

Trusting and adding a recovery device automatically: a device trusts the user's recovery device, as returned by `GET /v1/account/recovery-kit`, if `test_sig` verifies under the blob's `sign_pub`, and one of these holds: it created the kit itself; or `attest.sig` verifies under a device of the same user that is active in a log this device has verified; or the descriptor appears in a verified log, added with `via: "self"` by a device of the same user. A trusted recovery device is included in every genesis (10.7 step 3) and added automatically to every profile where this device is active and the recovery device is not (10.13 step 3.8), including profiles the user gains through a grant. An untrusted descriptor is never added; the options page then shows "Herstelsleutel kan niet worden gecontroleerd" with "Opnieuw maken".

Recovering:

1. The user has lost all devices. They log in (passkey on another device, or email code) and connect a new Chrome profile (10.4). Their profiles show as pending.
2. The options page offers "Herstellen met herstelsleutel" when `GET /v1/account/recovery-kit` reports a kit.
3. The user types the key. The client checks the checksum, fetches the blob, requires `iterations == 600000`, runs PBKDF2 and HKDF, decrypts, and imports both private keys as non-extractable `CryptoKey`s. It checks that: the public keys inside the plaintext equal the blob's `sign_pub` and `ecdh_pub` and the recovery descriptor in the logs; `test_sig` verifies; and a fresh signature by the imported signing key over `enc("ebs/v1/rk-check-sig", random 32 bytes)` verifies under `sign_pub` (the ECDH key is checked implicitly when the recovery wrap decrypts in step 4).
4. For each pending profile: fetch and verify the log, check that the recovery device is active, fetch the recovery device's wrap with `GET /v1/profiles/{id}/keys` (allowed for a pending device of a user whose recovery device is active in the profile; the response then contains only the wraps addressed to that recovery device, 11.9), unwrap it, build `add_device {device: new device, via: "recovery", verified: true}` authored and signed by the recovery device, wrap for the new device with `from` = the recovery device, and `POST /v1/profiles/{id}/log` with the new device's token. The server accepts entries authored by the recovery device only from a device of the same user.
5. The client offers to remove the lost devices (10.14) and recommends a new kit.
6. Recovery private keys are dropped from memory.

The kit is designed for single-user profiles (where nobody else can approve a new device), but it covers every profile of the user. The server holds only ciphertext under a 128-bit secret, so offline guessing is infeasible.

### 10.17 Profile deletion

1. The owner ("Profiel verwijderen" in the extension or dashboard, re-auth in the dashboard; the extension asks to type the profile label) or an admin (dashboard, re-auth) calls `DELETE /v1/profiles/{id}`.
2. The server sets `deleted_at = now`, `purge_at = now + 7 days`. All access stops immediately for everyone: record, log and key endpoints answer `410 profile_deleted`. The owner and admins can still call `POST /v1/profiles/{id}/restore` until `purge_at`. If an admin deleted it, the server emails the owner.
3. Devices that sync see `profile_deleted`, stop syncing the profile and ask the user "Profiel <naam> is verwijderd. Lokale kopie exporteren en daarna verwijderen?". The local copy is deleted only after the user confirms.
4. At `purge_at`, the cron job deletes records, log entries, wraps, history, meta, grants, `profile_devices` and the profile row. Audit events about the profile keep the profile id but no label.

### 10.18 Ownership transfer

1. The owner chooses a member with at least one active device ("Eigenaar maken").
2. The client appends `transfer_owner {user_id}`. The server swaps the roles in `profile_members`.

### 10.19 Account deletion

1. The user ("Account verwijderen" in the dashboard, re-auth, type the email address) or an admin calls `DELETE /v1/account` (or `DELETE /v1/admin/users/{id}`).
2. If the user owns profiles with other members, the server answers `409 owned_profiles_shared` with the list, unless the request says `{"owned_shared_profiles": "delete"}`. The user can transfer ownership first (10.18).
3. The server, in one batch: deletes owned profiles (immediately, without the 7-day grace, because the owner asked for deletion of everything), revokes all devices, deletes token hashes, sessions, passkeys, email login requests, the recovery kit, and the `users` row; sets the user's grants in other profiles to `revoked` and their devices there to `revoking`; pseudonymizes the user in audit events (13.3).
4. Remaining members' devices complete removal and rotation at their next sync (10.14).
5. Log entries in remaining profiles keep the deleted `user_id`, the device public keys and the user's encrypted display name, because the hash chain must stay verifiable. The server holds no plaintext name or email address for the user any more; only remaining members, who knew the name already, can decrypt the name in the log.
6. Records the user wrote in shared profiles remain: they belong to the profile.
7. The extension, on `401 account_deleted`, offers a decrypted export and then deletes all sync data and keys.

### 10.20 Export

- Server export, per user: `GET /v1/account/export` (session, re-auth). Everything the server holds about the user and the ciphertext of every profile the user can access. Format in 16.4.
- Server export, per profile: `GET /v1/profiles/{id}/export` (owner or member, session with re-auth or device token). Profile metadata, log, wraps addressed to the caller's devices, history, meta and all record envelopes.
- Extension export, per profile and for all profiles: "Exporteren" in the options page. The extension decrypts its local cache after a full sync and writes a JSON file through a download (format 16.4). Only the user's own extension can produce readable data.

---

## 11. API

### 11.1 Conventions

- Base: the instance origin (`ISSUER`). JSON API under `/v1`, OAuth under `/oauth`, dashboard under `/`.
- Requests and responses are `application/json; charset=utf-8` unless stated. Unknown request fields are rejected (`400 invalid_request`), so typos fail loudly. Unknown response fields MUST be ignored by clients.
- Every device request sends `EBS-Protocol: 1`. The server answers `426 upgrade_required` for unsupported versions.
- Schemas below use TypeScript notation. `B64<n>` is a base64url string of `n` decoded bytes. `Id<"p">` is a `p_` identifier. Fields marked `?` are optional. Timestamps are `number` (Unix ms).
- Lists are paginated with `limit` (default and maximum stated per endpoint) and an opaque `cursor` or `before`.
- No CORS headers are sent on any endpoint. The extension's service worker reaches the API through its host permission, which is not subject to CORS; the dashboard is same-origin. Browsers on other origins therefore cannot read responses.
- Security headers on every response: `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses. Dashboard HTML: the CSP in 14.3 (T9).
- Every API response carries `EBS-Server-Time: <Unix ms>` for clock offset correction (3.4).

### 11.2 Authentication schemes

`none`: unauthenticated, rate limited by IP.

`session`: cookie `__Host-ebs_session`. State-changing requests (all methods except GET and HEAD) MUST also carry `EBS-CSRF: 1` and an `Origin` header equal to `ISSUER`; otherwise `403 csrf`. `session+reauth`: additionally `elevated_until > now` (10.3).

Exception: the OAuth consent decision (`POST /oauth/authorize/decision`) is a top-level HTML form submission, because it must end in a navigation to the extension's redirect URI, and a form cannot set custom headers. It is exempt from `EBS-CSRF` and protected instead by all of: `Origin` equal to `ISSUER`; `Sec-Fetch-Site: same-origin` (requests without the header, from old browsers, are rejected; Chrome 116 and later always send it); and a hidden form field `csrf` that must equal `b64u(HMAC(SESSION_CSRF_KEY, enc("ebs/v1/csrf", session id hash, request_id)))`, bound to both the session and the authorization request. No other endpoint accepts form encoding.

`device`: four headers:

```
Authorization: EBS-Device ebs_dt_<..>
EBS-Timestamp: <Unix seconds>
EBS-Nonce: <B64<16>>
EBS-Signature: <B64<64>>
```

`EBS-Signature = ECDSA-Sign(sign_priv, enc("ebs/v1/req", ISSUER, method, path_and_query, u64(timestamp), nonce, H(body)))`, where `method` is upper case, `nonce` is the 16 decoded bytes of `EBS-Nonce` (fresh random per request), and `body` is the exact request body bytes (empty for GET). The server looks up the device by `H(token)`, rejects revoked or expired devices, checks `|now - timestamp| <= 300 s` and verifies the signature with the stored `sign_pub`.

URL normalisation for `path_and_query`: clients only build URLs whose path segments consist of `[A-Za-z0-9_.:-]` (ids are base64url) and whose query values consist of `[A-Za-z0-9_.-]`, so no percent-encoding ever occurs. Query parameters are sent in the order documented for each endpoint, without empty parameters, without a trailing `?` and without a fragment. The signed string is `url.pathname + url.search` of the `URL` object passed to `fetch`; the server uses `new URL(request.url).pathname + new URL(request.url).search`. With the restricted character set both sides produce the same string. The server rejects requests whose path or query contains other characters with `400 invalid_request` before verifying.

Replay: most state-changing device requests are idempotent or guarded by compare-and-set (record writes, log appends, deletes, PATCH, PUT). For the non-idempotent ones the server stores `(device_id, nonce)` in `request_nonces` for 10 minutes and rejects a repeated nonce with `409 replayed`: the token rotate grant of `/oauth/token`, `POST /v1/devices/recovery`, `POST /v1/profiles/{id}/grants`, `POST /v1/profiles/{id}/access-request`, `POST /v1/approvals/deny`, `POST /v1/profiles/{id}/rekey/lease` and `POST /v1/profiles/{id}/presence/ticket`. Successful requests update `devices.last_seen_at` at most once per hour (to limit writes and timing detail).

Recovery-device-authored log entries are sent with the authenticating device's credentials (10.16).

### 11.3 Errors

Error body:

```ts
{ error: { code: string, message: string, details?: object } }
```

`message` is English, for logs; clients translate `code` into Dutch UI text.

| HTTP | code | When |
|------|------|------|
| 400 | `invalid_request` | malformed JSON, unknown field, bad encoding, failed validation |
| 400 | OAuth codes: `invalid_grant`, `invalid_client`, `unsupported_grant_type`, `authorization_pending`, `slow_down`, `expired_token`, `access_denied` | `/oauth/*` endpoints, RFC 6749 and RFC 8628 shape: `{error, error_description}` |
| 401 | `unauthenticated` | no or unknown session or token |
| 401 | `invalid_signature` | device signature missing, wrong or outside the time window |
| 401 | `token_expired` | device token expired by inactivity; reconnect (10.6) |
| 401 | `account_deleted` | the account no longer exists |
| 403 | `forbidden` | authenticated but not allowed |
| 403 | `reauth_required` | needs `session+reauth` |
| 403 | `csrf` | CSRF header or Origin missing or wrong |
| 403 | `device_not_active` | device is pending or revoked in this profile |
| 403 | `registration_closed` | sign-up not allowed |
| 404 | `not_found` | unknown resource, or resource the caller may not know about |
| 404 | `user_not_found` | grant by email for unknown user and owners may not invite |
| 409 | `version_conflict` | at least one record write failed compare-and-set (details per item) |
| 409 | `stale_key_version` | write with a `kv` other than `current_kv` |
| 409 | `log_conflict` | log append with wrong `seq` or `prev`; details contain the server head |
| 409 | `lease_held` | another device holds the rekey lease |
| 409 | `owned_profiles_shared` | account deletion blocked; details list the profiles |
| 409 | `already_exists` | duplicate `profile_id` or similar |
| 409 | `replayed` | `EBS-Nonce` already used on a non-idempotent endpoint (11.2) |
| 410 | `profile_deleted` | profile is soft-deleted |
| 413 | `too_large` | body, record or batch over the cap |
| 422 | `log_invalid` | log entry fails signature or rule validation; details name the rule |
| 422 | `quota_exceeded` | per-profile or per-user quota reached |
| 426 | `upgrade_required` | unsupported protocol version |
| 429 | `rate_limited` | with `Retry-After` (seconds) |
| 503 | `unavailable` | D1 or email provider unavailable; with `Retry-After` |

### 11.4 Rate limits and size caps

Rate limits are enforced with the Workers Rate Limiting binding (approximate, per location) for request rates, and with D1 counters where precision matters (email sends, code attempts). Defaults, all configurable:

| Scope | Limit |
|-------|-------|
| `/oauth/authorize`, `/v1/auth/*` per IP | 30 per minute |
| Email sends per address | 3 per 15 minutes, 10 per day |
| Email sends per IP | 20 per hour |
| Email code verification per login request | 5 attempts, then the request is void |
| `/oauth/token` per IP | 20 per minute |
| `/oauth/pairing` per IP | 5 per 10 minutes |
| User code entry per session | 5 failures per 10 minutes |
| Device requests per device | 120 per minute |
| `records:put` per device | 60 requests and 2,000 records per minute |
| `records:put` per profile (all devices) | 6,000 records per minute |
| Record pulls per device | 60 requests per minute |
| Rekey batches per profile | 30 per minute |
| Log appends per profile | 30 per minute, and 500 entries per day |
| Log appends per device | 10 per minute |
| Export per user | 5 per day |
| Admin endpoints per session | 120 per minute |
| Teamwerk tickets per device | 10 per minute |
| Teamwerk frames per connection | 20 per second, burst 30 (18.11) |

Size caps:

| Item | Cap |
|------|-----|
| Request body, `records:put` | 2 MiB |
| Request body, log append (`POST .../log`, `POST /v1/profiles`) | 512 KiB |
| Request body, other endpoints | 256 KiB |
| Record `ct` | 65,552 bytes decoded (64 KiB bucket plus tag) |
| Writes per `records:put` | 200 |
| Ids per `records:get` | 500 |
| Records per pull page | 500 or 4 MiB of response, whichever comes first |
| Log entries per append | 50 |
| Wraps per append | 160 |
| Active devices per profile, including recovery devices | 150 |
| Log entries per profile | 10,000 (removals with their rotation up to 10,500, 9.8) |
| Profile label, device name | 64 characters |
| User display name | 100 characters |
| Email | 254 characters |
| Live records per profile | 200,000 |
| Stored ciphertext per profile | 512 MiB |
| Profiles owned per user | 200 |
| Members per profile | 50 |
| Browser devices per user | 20 |
| Teamwerk binary frame | 1,280 bytes |
| Teamwerk room | 25 sockets |

D1 limits the number of statements per Worker invocation and the size of a batch. Servers MUST apply record batches with a bounded number of statements (set-based statements over `json_each(?)`), never one statement per record.

### 11.5 OAuth endpoints

#### `GET /oauth/authorize`

Auth: none (renders login and consent). Query parameters as in 10.4 step 6. Validation as in 10.4 step 7. The server stores the validated request as `authorize_requests` (12) with a random `request_id` and renders the login and consent pages; later steps reference only `request_id`, never re-sent parameters.

#### `POST /oauth/authorize/decision`

Auth: session (logged in within the last 5 minutes with user verification). CSRF protection by the form exception in 11.2 (`Origin`, `Sec-Fetch-Site`, `csrf` field), not `EBS-CSRF`.

```
// request: Content-Type: application/x-www-form-urlencoded
request_id=<..>&csrf=<..>&decision=approve        (or decision=deny)

// response: 303 See Other
Location: <redirect_uri>?code=..&state=..&iss=..
       or <redirect_uri>?error=access_denied&state=..&iss=..
```

The consent page's CSP `form-action` lists `'self'` only; Chrome applies `form-action` to the redirect that follows a form submission, so the consent page response adds the single validated redirect origin `https://<client_id>.chromiumapp.org` to it (14.3, T9).

#### `POST /oauth/pairing`

Auth: none.

```ts
// request
{ client_id: string, device_jkt: B64<32>, device_name: string }
// response 200
{ pairing_secret: B64<32>, user_code: string, verification_uri: string, expires_in: 600, interval: 5 }
```

#### `POST /v1/pairing/lookup` and `POST /v1/pairing/approve`

Auth: session; `approve` needs session+reauth.

```ts
// lookup request
{ user_code: string }
// lookup response 200
{ device_name: string, device_code: string, client_id: string, created_at: number }
// approve request
{ user_code: string, approve: boolean }
// approve response 204
```

#### `POST /oauth/token`

Auth: none for `authorization_code` and `pairing`; device for `rotate`. Content type `application/json` (a documented deviation from RFC 6749, which uses form encoding, because the request carries structured device keys).

```ts
type DeviceRegistration = {
  sign_pub: B64<65>, ecdh_pub: B64<65>,
  name: string,                       // "Chrome op MacBook"
  platform: "mac" | "win" | "linux" | "cros" | "other"
}

// grant_type authorization_code
{ grant_type: "authorization_code", code: string, code_verifier: string,
  client_id: string, redirect_uri: string,
  device: DeviceRegistration, device_proof: B64<64> }

// grant_type pairing
{ grant_type: "urn:ebs:params:oauth:grant-type:pairing", pairing_secret: B64<32>,
  client_id: string, device: DeviceRegistration, device_proof: B64<64> }

// grant_type rotate (device auth headers present)
{ grant_type: "urn:ebs:params:oauth:grant-type:rotate" }

// response 200
{ access_token: string,               // "ebs_dt_..."
  token_type: "EBS-Device",
  device_id: Id<"d">,
  rotate_after: number,               // now + 30 days
  user: { id: Id<"u">, email: string, name: string, is_admin: boolean },
  issuer: string }
```

`device_proof = ECDSA-Sign(sign_priv, enc("ebs/v1/token-proof", grant_value, client_id, H(sign_pub), H(ecdh_pub)))` where `grant_value` is the code or the pairing secret string. It proves possession of the private key whose public key is bound by `device_jkt`, so a stolen code or pairing secret cannot be redeemed with other keys.

#### `POST /oauth/revoke`

Auth: device (the token being revoked). Body `{ token: string }`. Response `200 {}` always. Revokes the device (10.6).

### 11.6 Dashboard authentication endpoints

| Method and path | Auth | Request | Response |
|-----------------|------|---------|----------|
| `POST /v1/auth/email/start` | none | `{ email: string, purpose: "login" \| "signup" }` | `202 { login_request_id: string }` |
| `POST /v1/auth/email/verify` | none | `{ login_request_id: string, code: string }` | `200 { user: User }` plus session cookie |
| `POST /v1/auth/setup` | none | `{ token: string }` | `200 { user: User }` plus session cookie |
| `POST /v1/auth/webauthn/register/options` | session | `{}` | `200 PublicKeyCredentialCreationOptionsJSON` plus `challenge_id` |
| `POST /v1/auth/webauthn/register/verify` | session | `{ challenge_id, credential: RegistrationResponseJSON, name: string }` | `201 { passkey: Passkey }` |
| `POST /v1/auth/webauthn/login/options` | none | `{}` | `200 PublicKeyCredentialRequestOptionsJSON` plus `challenge_id` |
| `POST /v1/auth/webauthn/login/verify` | none | `{ challenge_id, credential: AuthenticationResponseJSON }` | `200 { user: User }` plus session cookie |
| `POST /v1/auth/reauth/options` | session | `{}` | passkey request options, or `{ method: "email", login_request_id }` when the user has no passkey |
| `POST /v1/auth/reauth/verify` | session | `{ challenge_id, credential }` or `{ login_request_id, code }` | `200 { elevated_until: number }` |
| `GET /v1/auth/session` | session | | `200 { user: User, elevated_until: number \| null, expires_at: number }` |
| `POST /v1/auth/logout` | session | `{}` | `204` |

The JSON forms of WebAuthn options and responses follow WebAuthn Level 3 (`toJSON` / `parseCreationOptionsFromJSON`), base64url fields.

```ts
type User = { id: Id<"u">, email: string, name: string, is_admin: boolean,
              email_login: boolean, created_at: number }
type Passkey = { id: string, name: string, created_at: number, last_used_at: number | null,
                 backup_eligible: boolean, backup_state: boolean }
```

### 11.7 Account and devices

| Method and path | Auth | Request | Response |
|-----------------|------|---------|----------|
| `GET /v1/account` | session or device | | `200 { user: User, passkeys: Passkey[], has_recovery_kit: boolean }` |
| `PATCH /v1/account` | session (`email_login`: session+reauth) | `{ name?: string, email_login?: boolean }` | `200 { user: User }` |
| `DELETE /v1/account` | session+reauth | `{ confirm_email: string, owned_shared_profiles?: "delete" }` | `204`, or `409 owned_profiles_shared` |
| `PATCH /v1/account/passkeys/{id}` | session | `{ name: string }` | `200 { passkey: Passkey }` |
| `DELETE /v1/account/passkeys/{id}` | session+reauth | | `204`; `403 forbidden` if it is the last passkey and email login is disabled (the user would be locked out) |
| `GET /v1/account/recovery-kit` | device | | `200 RecoveryKit` or `404` |
| `PUT /v1/account/recovery-kit` | device | `RecoveryKit` without `created_at` | `201` |
| `DELETE /v1/account/recovery-kit/{recovery_device_id}` | device or session+reauth | | `204` |
| `GET /v1/devices` | session or device | | `200 { devices: Device[] }` (own devices; admins add `?user_id=`) |
| `GET /v1/devices/self` | device | | `200 { device: Device }` |
| `PATCH /v1/devices/{id}` | session or device (own) | `{ name: string }` | `200 { device: Device }` |
| `DELETE /v1/devices/{id}` | session+reauth (own, or admin) | | `204` (revokes, 10.6) |
| `POST /v1/devices/recovery` | device | `{ sign_pub: B64<65>, ecdh_pub: B64<65> }` | `201 { device: Device }` |

```ts
type Device = {
  id: Id<"d">, user_id: Id<"u">, kind: "browser" | "recovery",
  name: string, platform: string, sign_pub: B64<65>, ecdh_pub: B64<65>,
  created_at: number, last_seen_at: number | null,
  token_created_at: number | null, token_last_used_at: number | null,
  revoked_at: number | null
}
type RecoveryKit = {
  sign_pub: B64<65>, ecdh_pub: B64<65>,          // public keys of the recovery device (5.5)
  test_sig: B64<64>,                             // recovery key's signature over its own descriptor
  attest: { device_id: Id<"d">, sig: B64<64> },  // creating device's attestation
  v: 1, user_id: Id<"u">, recovery_device_id: Id<"d">,
  salt: B64<16>, iterations: 600000, nonce: B64<12>, ct: string /* b64u */,
  created_at: number
}
```

The dashboard's "Apparaten en tokens" page shows each device with its device code (computed in the dashboard from the public keys, informational only, since the dashboard is server-served code), name, platform, created, last seen (hour granularity), token created and last used, and a "Intrekken" button.

### 11.8 Profiles, grants and approvals

```ts
type ProfileSummary = {
  id: Id<"p">, label: string,
  owner: { id: Id<"u">, name: string, email: string },
  my_role: "owner" | "member",
  my_status: "pending" | "active" | "denied",       // grant status of the caller
  my_device_status?: "pending" | "active" | "revoking",  // device auth only
  head: { seq: number, hash: B64<32> },
  current_kv: number,
  meta_version: number, meta_kv: number, meta_nonce: B64<12>, meta_ct: string,  // omitted unless my_device_status is active
  change_seq: number,
  member_count: number, record_count: number,
  rekey_pending: boolean, rotation_recommended: boolean,
  pending_removals: Array<{ device_id: Id<"d">, user_id: Id<"u">, reason: "device_revoked" | "grant_revoked" | "account_deleted" }>,
  approvals_pending: number,       // requests this device may approve (device auth only)
  created_at: number, deleted_at: number | null
}
```

| Method and path | Auth | Request | Response |
|-----------------|------|---------|----------|
| `GET /v1/profiles` | device or session | | `200 { profiles: ProfileSummary[] }` (max 1,000; larger sets paginate with `cursor`) |
| `POST /v1/profiles` | device | `{ profile_id, label, genesis: LogEntry, wraps: Wrap[], meta: Meta }` | `201 { profile: ProfileSummary }` |
| `GET /v1/profiles/{id}` | device or session (member, or admin) | | `200 { profile: ProfileSummary }` |
| `PATCH /v1/profiles/{id}` | owner (device or session) | `{ label: string }` | `200 { profile }` |
| `DELETE /v1/profiles/{id}` | owner (device, or session+reauth), admin (session+reauth) | | `202 { purge_at: number }` |
| `POST /v1/profiles/{id}/restore` | owner or admin | `{}` | `200 { profile }` |
| `GET /v1/profiles/{id}/members` | member or admin | | `200 { members: Member[] }` |
| `POST /v1/profiles/{id}/grants` | owner | `{ email: string }` | `201 { member: Member }` |
| `DELETE /v1/profiles/{id}/grants/{user_id}` | owner, admin, or the user themselves (leave) | | `202` (grant `revoked`, devices `revoking`) |
| `GET /v1/approvals` | device | | `200 { requests: ApprovalRequest[] }` |
| `POST /v1/approvals/deny` | device (approver-eligible) | `{ profile_id, user_id, reason: "denied" \| "code_mismatch" }` | `204` |
| `POST /v1/profiles/{id}/access-request` | device whose user has an `active` grant and whose row is `removed` or `denied` | `{}` | `202` (row becomes `pending`, 10.9) |

```ts
type Member = {
  user: { id: Id<"u">, name: string, email: string },
  role: "owner" | "member",
  status: "pending" | "active" | "denied" | "revoked",
  granted_by: { id: Id<"u">, name: string } | null, granted_at: number,
  devices: Array<{ device_id: Id<"d">, kind: "browser" | "recovery", name: string, platform: string,
                   sign_pub: B64<65>, ecdh_pub: B64<65>,
                   status: "pending" | "active" | "revoking" | "removed", added_seq: number | null }>
}
type ApprovalRequest = {
  profile_id: Id<"p">, profile_label: string,
  kind: "new_member" | "own_device" | "member_device",
  user: { id: Id<"u">, name: string, email: string },
  granted_by: { id: Id<"u">, name: string } | null,
  devices: Array<{ device_id: Id<"d">, name: string, platform: string, sign_pub: B64<65>, ecdh_pub: B64<65>, created_at: number }>,
  requested_at: number
}
```

The server includes in `/v1/approvals` only requests the calling device may approve per the log rules (it knows the policy from the log), and only for profiles with `auto_approve = false`, unless the device is going to auto-approve (it returns them with `auto: true`).

Leaving: the leaving user's client calls `DELETE /v1/profiles/{id}/grants/{own user_id}`. The leaver never authors the removal and rotation itself, because the author of a rotation learns the new key (9.4 rule: the author of a removal may not be removed by it). A remaining member completes it.

### 11.9 Membership log, keys and meta

| Method and path | Auth | Request | Response |
|-----------------|------|---------|----------|
| `GET /v1/profiles/{id}/log?after=<seq>&limit=<n>` | device (pending or active in the profile) or session (member) | `limit` default and max 500 | `200 { entries: LogEntry[], head: {seq, hash}, has_more: boolean }` |
| `POST /v1/profiles/{id}/log` | device (active, or a device of the same user as a recovery author) | `{ entries: LogEntry[], wraps?: Wrap[], history?: History, meta?: MetaUpdate }` | `200 { head: {seq, hash} }`; `409 log_conflict`; `422 log_invalid` |
| `GET /v1/profiles/{id}/keys` | device: active, or pending when its user has an active recovery device in the profile | | `200 { current_kv: number, wraps: Wrap[], history: History[] }`. For an active device: the wraps addressed to it. For a pending device: only the wraps addressed to its user's active recovery device (for recovery, 10.16), and the history. |
| `PUT /v1/profiles/{id}/meta` | device (active) | `MetaUpdate` | `200 { meta_version }`; `409 version_conflict` |

```ts
type LogEntry = { body_jcs: string /* exact canonical body, 9.1 */, sig: B64<64>,
                  hash?: B64<32> /* in responses only, informational; clients recompute */ }
type EncName = { nonce: B64<12>, ct: string /* b64u, 144 or 528 bytes */ }
type Wrap = { v: 1, profile_id, kv: number, to: Id<"d">, from: Id<"d">, at: number,
              epk: B64<65>, nonce: B64<12>, ct: B64<80>, sig: B64<64> }
type History = { v: 1, profile_id, kv: number, nonce: B64<12>, ct: B64<48> }
type Meta = { meta_version: number, meta_kv: number, meta_nonce: B64<12>, meta_ct: string }
type MetaUpdate = Meta & { base_meta_version: number }
```

A pending device may read the log (so the grantee can verify the profile right after approval and show the owner's identity) but not keys, meta or records.

### 11.10 Instance metadata and configuration

`GET /v1/meta` (auth none):

```ts
{ issuer: string, protocol_versions: [1], instance_name: string, rp_id: string,
  registration: "closed" | "open",
  authorization_endpoint: string, token_endpoint: string, pairing_endpoint: string,
  revocation_endpoint: string, email_login: boolean,
  limits: { record_ct_max: 65552, put_batch_max: 200, get_batch_max: 500, pull_page_max: 500 } }
```

Configuration (Worker vars and secrets):

| Name | Kind | Default | Meaning |
|------|------|---------|---------|
| `ISSUER` | var | required | public origin |
| `RP_ID` | var | host of `ISSUER` | WebAuthn RP id |
| `INSTANCE_NAME` | var | `EB Sessions Sync` | shown on pages |
| `ADMIN_EMAILS` | var | required | admins |
| `ALLOWED_EXTENSION_IDS` | var | Web Store id of EB Sessions | OAuth client allow-list |
| `REGISTRATION` | var | `closed` | self sign-up |
| `OWNERS_CAN_INVITE` | var | `false` | owners may create accounts by sharing |
| `EMAIL_LOGIN` | var | `true` | allow email login codes at all |
| `EMAIL_NOTIFICATIONS` | var | `true` | grant and approval emails |
| `SESSION_CSRF_KEY` | secret | required | HMAC key for the consent form `csrf` field |
| `AUDIT_DAYS` | var | `365` | audit retention |
| `INACTIVE_ACCOUNT_DAYS` | var | `0` (off) | delete accounts inactive this long, after a warning email 30 days before |
| `EMAIL_PROVIDER`, `EMAIL_API_KEY`, `EMAIL_FROM` | var / secret | required for email | outbound mail |
| `TEAMWERK_ENABLED` | var | `true` | allow Teamwerk tickets |
| `ROOM_CAP` | var | `25` | sockets per Teamwerk room |
| `PRESENCE_TICKET_KEY` | secret | required when Teamwerk is enabled | 32-byte HMAC key for room tickets |

### 11.11 Records

```ts
type Envelope = { id: B64<32>, version: number, kv: number, deleted: boolean, nonce: B64<12>, ct: string }
type StoredEnvelope = Envelope & { change_seq: number, updated_at: number, updated_by: Id<"d"> }
```

#### `GET /v1/profiles/{id}/records?since=<cursor>&limit=<n>`

Auth: device, active in the profile. `since` omitted means from the start. `limit` default and max 500.

```ts
// 200
{ records: StoredEnvelope[], cursor: string, has_more: boolean }
```

Records are ordered by `change_seq` ascending. `cursor` encodes the last `change_seq` returned (or the request cursor if none). Cursors never expire, because tombstones are kept for the life of the profile (8.8).

#### `POST /v1/profiles/{id}/records:get`

Auth: device, active. Request `{ ids: B64<32>[] }` (max 500). Response `200 { records: StoredEnvelope[], missing: B64<32>[] }`.

#### `POST /v1/profiles/{id}/records:put`

Auth: device, active. This endpoint also performs deletes (op `delete`, carrying an encrypted tombstone) and rekeys.

```ts
// request
{ lease_id?: string,                 // required when any op is "rekey"
  writes: Array<
    | { op: "upsert" | "delete", id: B64<32>, base_version: number, version: number,
        kv: number, nonce: B64<12>, ct: string }
    | { op: "rekey", id: B64<32>, version: number, from_kv: number,
        kv: number, nonce: B64<12>, ct: string }
  > }

// response: 200 if every item is ok or skipped, 409 version_conflict if at least one conflict
{ results: Array<
    | { id, status: "ok", version: number, change_seq: number }
    | { id, status: "skipped" }                          // rekey whose precondition no longer holds
    | { id, status: "conflict", current: StoredEnvelope | null }
  >,
  cursor_hint: string }
```

Server rules per item:

1. `upsert` and `delete`: `version == base_version + 1`, `kv == current_kv` (else the whole request fails with `409 stale_key_version`), `deleted` is `op == "delete"`, `ct` within the cap. Compare-and-set on `base_version`.
2. `rekey`: `kv == current_kv`, `from_kv < current_kv`, valid lease. Compare-and-set on `(version, from_kv)`. Does not change `change_seq` or `updated_at`.
3. Items are independent (non-atomic batch). Accepted items get strictly increasing `change_seq` values in request order; gaps are allowed.
4. Duplicate `id` in one request: `400 invalid_request`.
5. Quotas: if the batch would exceed the live record or byte quota, the whole request fails with `422 quota_exceeded` before any write.

`cursor_hint` lets the writer advance its own cursor past its own writes when nothing else changed in between (it equals the cursor before the request if no foreign writes intervened, else it is omitted). Clients MAY ignore it.

### 11.12 Rekey

| Method and path | Auth | Request | Response |
|-----------------|------|---------|----------|
| `POST /v1/profiles/{id}/rekey/lease` | device, active | `{ kv: number }` | `200 { lease_id, expires_at, remaining }`; `204`; `409 lease_held { expires_at }` |
| `GET /v1/profiles/{id}/rekey/batch?lease_id=..&after=..&limit=..` | device, lease holder | `after` empty or a `next_after` value; `limit` max 200 | `200 { records: StoredEnvelope[], next_after: string \| null }`, all with `kv < current_kv`, ordered by `(kv, id)`, strictly after `after` |
| `POST /v1/profiles/{id}/rekey/complete` | device, lease holder | `{ lease_id, kv }` | `200 { remaining: number, cleared: boolean }` (10.15 step 5) |

### 11.13 Audit log

`GET /v1/audit?scope=<scope>&before=<id>&limit=<n>` (session; `limit` max 200).

| scope | Who | Contents |
|-------|-----|----------|
| `account` | the user | events where the user is actor or subject |
| `profile:<id>` | the owner, members, admins | events about the profile |
| `instance` | admins | all events |

```ts
// 200
{ events: Array<{ id: string, at: number, action: string,
                  actor: { user_id: Id<"u"> | null, name: string | null, device_id: Id<"d"> | null },
                  subject?: { user_id?: Id<"u">, device_id?: Id<"d">, profile_id?: Id<"p"> },
                  ip_prefix: string | null, ua_family: string | null, details: object }>,
  next_before: string | null }
```

Actions are listed in 13.2.

### 11.14 Export

| Method and path | Auth | Response |
|-----------------|------|----------|
| `GET /v1/account/export` | session+reauth | `200 application/x-ndjson`, `Content-Disposition: attachment; filename="ebs-account-<user_id>-<date>.ndjson"` (format 16.4) |
| `GET /v1/profiles/{id}/export` | member (device, or session+reauth) | `200 application/x-ndjson` (format 16.4) |

Responses are streamed. Each export is recorded in the audit log.

### 11.15 Admin

All admin endpoints require session with `is_admin`; mutations require session+reauth.

| Method and path | Request | Response |
|-----------------|---------|----------|
| `GET /v1/admin/users?cursor=&q=` | | `200 { users: Array<User & { status: "invited" \| "active" \| "disabled", last_login_at, device_count, profile_count }>, cursor }` |
| `POST /v1/admin/users` | `{ email, name, is_admin?: false, delivery: "email" \| "link" }` | `201 { user, setup_link?: string }` (link only for `delivery = link`, shown once) |
| `PATCH /v1/admin/users/{id}` | `{ name?, disabled?: boolean, resend_setup?: "email" \| "link" }` | `200 { user, setup_link? }` |
| `DELETE /v1/admin/users/{id}` | `{ owned_shared_profiles?: "delete" }` | `204` or `409 owned_profiles_shared` |
| `GET /v1/admin/profiles?cursor=&owner=` | | `200 { profiles: Array<{ id, label, owner, member_count, pending_count, record_count, byte_count, current_kv, auto_approve, created_at, deleted_at }>, cursor }` |
| `POST /v1/admin/grants` | `{ user_id, profile_id }` | `201 { member: Member }` (status `pending`) |
| `DELETE /v1/admin/grants/{profile_id}/{user_id}` | | `202` |

`is_admin` cannot be set through the API for addresses outside `ADMIN_EMAILS`; admin status follows the configuration so that a compromised admin session cannot mint new admins. Disabling a user revokes their sessions and devices (devices become `revoking` in their profiles).

### 11.16 Dashboard pages

The dashboard is a static app using only the endpoints above. Pages:

| Page | Who | Shows and does |
|------|-----|----------------|
| Inloggen | everyone | passkey login, email code fallback |
| Account | user | name, email, passkeys (add, rename, remove), email login switch, recovery kit status, export, delete account |
| Apparaten en tokens | user (admin: any user) | devices with device code, platform, created, last seen, token created and last used, revoke |
| Profielen | user (admin: all) | profiles with label, owner, role, member count, record count, key version, auto-approve flag, pending approvals; rename (owner), delete and restore (owner, admin) |
| Leden | owner, members, admin | members and their devices with status (`wacht op goedkeuring`, `actief`, `geweigerd`, `ingetrokken`), role, granted by, `verified`; grant access (owner, admin), revoke (owner, admin), leave (self) |
| Gebruikers | admin | create accounts (email invite or set-up link), disable, resend set-up, delete |
| Auditlog | user (own), owner and members (profile), admin (instance) | events from 13.2, filterable by scope and action |
| Koppelen | user | pairing code entry (10.5) |
| Toestemming | user | OAuth consent page (10.4 step 9) |

Role changes and approvals are not available in the dashboard, because they require keys; the members page links to "Open EB Sessions om toegang goed te keuren".

The dashboard has no Teamwerk view. Presence exists only in the extension.

### 11.17 Teamwerk endpoints

#### `POST /v1/profiles/{id}/presence/ticket`

Auth: device, active in the profile, with request signature. Body `{}`.

```ts
// 200
{ ticket: string,            // 18.5
  ws_url: string,            // "wss://<host>/v1/presence/ws"
  protocol: "ebs.v1",
  expires_at: number,        // now + 60 s
  kv: number }
```

Errors: `403 device_not_active`, `403 forbidden` (Teamwerk disabled on the instance), `410 profile_deleted`, `429 rate_limited` (10 per minute per device).

#### `GET /v1/presence/ws`

Auth: room ticket. WebSocket upgrade.

```
GET /v1/presence/ws HTTP/1.1
Upgrade: websocket
Origin: chrome-extension://<allowed extension id>
Sec-WebSocket-Protocol: ebs.v1, ebs.ticket.<ticket>
```

Success: `101 Switching Protocols` with `Sec-WebSocket-Protocol: ebs.v1`, then the frames of 18.7. Failure before the upgrade: `401 unauthenticated` (bad, expired or reused ticket), `403 forbidden` (Origin not allowed), `409 stale_key_version` (ticket `kv` below the room's), `429 rate_limited`, `503 unavailable`. Room-level rejections after the upgrade use the close codes of 18.4 (for example 4029 when the room is full).

---

## 12. D1 schema

Migration `0001_init.sql`. All `*_at` columns are Unix ms. Binary values are stored as BLOB; ids as TEXT. `STRICT` tables catch type errors.

```sql
PRAGMA foreign_keys = ON;

CREATE TABLE users (
  id                TEXT PRIMARY KEY,
  email             TEXT NOT NULL COLLATE NOCASE UNIQUE,
  name              TEXT NOT NULL,
  status            TEXT NOT NULL CHECK (status IN ('invited','active','disabled')),
  is_admin          INTEGER NOT NULL DEFAULT 0,
  email_login       INTEGER NOT NULL DEFAULT 1,
  webauthn_handle   BLOB NOT NULL,              -- 16 random bytes, WebAuthn user.id
  email_verified_at INTEGER,
  created_at        INTEGER NOT NULL,
  last_login_at     INTEGER,
  inactivity_warned_at INTEGER
) STRICT;

CREATE TABLE passkeys (
  id              TEXT PRIMARY KEY,             -- credential id, b64u
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key      BLOB NOT NULL,                -- COSE key
  alg             INTEGER NOT NULL,
  sign_count      INTEGER NOT NULL,
  transports      TEXT,                         -- JSON array
  aaguid          TEXT,
  backup_eligible INTEGER NOT NULL,
  backup_state    INTEGER NOT NULL,
  name            TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER
) STRICT;
CREATE INDEX passkeys_user ON passkeys(user_id);

CREATE TABLE webauthn_challenges (
  id          TEXT PRIMARY KEY,
  challenge   BLOB NOT NULL,
  user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
  purpose     TEXT NOT NULL CHECK (purpose IN ('register','login','reauth')),
  expires_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE email_logins (
  id          TEXT PRIMARY KEY,                 -- login_request_id
  email       TEXT NOT NULL COLLATE NOCASE,
  purpose     TEXT NOT NULL CHECK (purpose IN ('login','signup','reauth')),
  code_hash   BLOB,                             -- NULL when no mail was sent (unknown address)
  attempts    INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX email_logins_email ON email_logins(email, created_at);

CREATE TABLE setup_tokens (
  token_hash  BLOB PRIMARY KEY,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  INTEGER NOT NULL,
  used_at     INTEGER,
  created_by  TEXT REFERENCES users(id) ON DELETE SET NULL
) STRICT;

CREATE TABLE sessions (
  id_hash        BLOB PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at     INTEGER NOT NULL,
  last_seen_at   INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  uv_at          INTEGER NOT NULL,              -- last user-verified authentication
  elevated_until INTEGER,
  ua_family      TEXT
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE authorize_requests (
  id              TEXT PRIMARY KEY,             -- request_id
  client_id       TEXT NOT NULL,
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  state           TEXT NOT NULL,
  device_jkt      TEXT NOT NULL,
  device_name     TEXT NOT NULL,
  expires_at      INTEGER NOT NULL              -- 10 minutes
) STRICT;

CREATE TABLE oauth_codes (
  code_hash       BLOB PRIMARY KEY,
  client_id       TEXT NOT NULL,
  redirect_uri    TEXT NOT NULL,
  code_challenge  TEXT NOT NULL,
  device_jkt      TEXT NOT NULL,
  user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at      INTEGER NOT NULL,             -- now + 60 s
  used_at         INTEGER,
  device_id       TEXT                          -- set on redemption, for replay revocation
) STRICT;

CREATE TABLE pairings (
  secret_hash   BLOB PRIMARY KEY,
  user_code     TEXT NOT NULL UNIQUE,
  client_id     TEXT NOT NULL,
  device_jkt    TEXT NOT NULL,
  device_name   TEXT NOT NULL,
  status        TEXT NOT NULL CHECK (status IN ('pending','approved','denied','redeemed')),
  user_id       TEXT REFERENCES users(id) ON DELETE CASCADE,
  last_poll_at  INTEGER,
  expires_at    INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
) STRICT;

CREATE TABLE devices (
  id                    TEXT PRIMARY KEY,
  user_id               TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind                  TEXT NOT NULL CHECK (kind IN ('browser','recovery')),
  name                  TEXT NOT NULL,
  platform              TEXT NOT NULL,
  client_id             TEXT,                   -- extension id
  sign_pub              BLOB NOT NULL,
  ecdh_pub              BLOB NOT NULL,
  device_jkt            TEXT NOT NULL,
  token_hash            BLOB UNIQUE,
  token_created_at      INTEGER,
  token_last_used_at    INTEGER,
  prev_token_hash       BLOB UNIQUE,
  prev_token_expires_at INTEGER,
  created_at            INTEGER NOT NULL,
  last_seen_at          INTEGER,
  revoked_at            INTEGER
) STRICT;
CREATE INDEX devices_user ON devices(user_id);
CREATE INDEX devices_jkt ON devices(user_id, device_jkt);

CREATE TABLE recovery_kits (
  recovery_device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  user_id            TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sign_pub           BLOB NOT NULL,
  ecdh_pub           BLOB NOT NULL,
  salt               BLOB NOT NULL,
  iterations         INTEGER NOT NULL CHECK (iterations = 600000),
  nonce              BLOB NOT NULL,
  ct                 BLOB NOT NULL,
  test_sig           BLOB NOT NULL,
  attest_device_id   TEXT NOT NULL,
  attest_sig         BLOB NOT NULL,
  created_at         INTEGER NOT NULL
) STRICT;
CREATE INDEX recovery_kits_user ON recovery_kits(user_id);

CREATE TABLE profiles (
  id                   TEXT PRIMARY KEY,
  owner_id             TEXT NOT NULL REFERENCES users(id),
  label                TEXT NOT NULL,
  current_kv           INTEGER NOT NULL DEFAULT 1,
  writes_at_kv         INTEGER NOT NULL DEFAULT 0,
  change_seq           INTEGER NOT NULL DEFAULT 0,
  log_head_seq         INTEGER NOT NULL,
  log_head_hash        BLOB NOT NULL,
  approvers            TEXT NOT NULL DEFAULT 'members',   -- mirror of the log policy
  auto_approve         INTEGER NOT NULL DEFAULT 0,        -- mirror of the log policy
  meta_version         INTEGER NOT NULL,
  meta_kv              INTEGER NOT NULL,
  meta_nonce           BLOB NOT NULL,
  meta_ct              BLOB NOT NULL,
  record_count         INTEGER NOT NULL DEFAULT 0,
  byte_count           INTEGER NOT NULL DEFAULT 0,
  rekey_pending        INTEGER NOT NULL DEFAULT 0,
  rekey_lease_id       TEXT,
  rekey_lease_device   TEXT,
  rekey_lease_expires  INTEGER,
  created_at           INTEGER NOT NULL,
  deleted_at           INTEGER,
  purge_at             INTEGER
) STRICT;
CREATE INDEX profiles_owner ON profiles(owner_id);
CREATE INDEX profiles_purge ON profiles(purge_at) WHERE purge_at IS NOT NULL;

CREATE TABLE profile_members (
  profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('owner','member')),
  status      TEXT NOT NULL CHECK (status IN ('pending','active','denied','revoked')),
  granted_by  TEXT REFERENCES users(id) ON DELETE SET NULL,
  granted_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  PRIMARY KEY (profile_id, user_id)
) STRICT;
CREATE INDEX profile_members_user ON profile_members(user_id, status);

CREATE TABLE profile_devices (
  profile_id   TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  device_id    TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  user_id      TEXT NOT NULL,
  status       TEXT NOT NULL CHECK (status IN ('pending','active','revoking','removed','denied')),
  verified     INTEGER,                         -- from the add_device entry
  via          TEXT,                            -- grant | self | auto | recovery | genesis
  added_seq    INTEGER,
  removed_seq  INTEGER,
  requested_at INTEGER NOT NULL,
  PRIMARY KEY (profile_id, device_id)
) STRICT;
CREATE INDEX profile_devices_status ON profile_devices(profile_id, status);
CREATE INDEX profile_devices_device ON profile_devices(device_id);

CREATE TABLE log_entries (
  profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  seq         INTEGER NOT NULL,
  type        TEXT NOT NULL,
  author      TEXT NOT NULL,
  body_jcs    TEXT NOT NULL,                    -- exact body_jcs as received and verified
  sig         BLOB NOT NULL,
  hash        BLOB NOT NULL,                    -- H(enc("ebs/v1/log-hash", body_jcs)), body only
  created_at  INTEGER NOT NULL,                 -- server time
  PRIMARY KEY (profile_id, seq)
) STRICT, WITHOUT ROWID;

CREATE TABLE wrapped_keys (
  profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  kv          INTEGER NOT NULL,
  device_id   TEXT NOT NULL,
  wrap_json   TEXT NOT NULL,                    -- the Wrap object
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (profile_id, device_id, kv)
) STRICT, WITHOUT ROWID;

CREATE TABLE key_history (
  profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  kv          INTEGER NOT NULL,                 -- the newer version; blob holds DK_(kv-1)
  nonce       BLOB NOT NULL,
  ct          BLOB NOT NULL,
  PRIMARY KEY (profile_id, kv)
) STRICT, WITHOUT ROWID;

CREATE TABLE records (
  profile_id  TEXT NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  id          TEXT NOT NULL,                    -- rid, 43 chars
  version     INTEGER NOT NULL,
  kv          INTEGER NOT NULL,
  deleted     INTEGER NOT NULL,
  nonce       BLOB NOT NULL,
  ct          BLOB NOT NULL,
  size        INTEGER NOT NULL,                 -- length(ct), for quotas
  change_seq  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL,
  updated_by  TEXT NOT NULL,
  PRIMARY KEY (profile_id, id)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX records_changes ON records(profile_id, change_seq);
CREATE INDEX records_kv ON records(profile_id, kv, id);

CREATE TABLE request_nonces (
  device_id   TEXT NOT NULL,
  nonce       BLOB NOT NULL,
  expires_at  INTEGER NOT NULL,                 -- now + 10 minutes
  PRIMARY KEY (device_id, nonce)
) STRICT, WITHOUT ROWID;
CREATE INDEX request_nonces_expiry ON request_nonces(expires_at);

CREATE TABLE audit_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  at          INTEGER NOT NULL,
  action      TEXT NOT NULL,
  actor_user  TEXT,
  actor_device TEXT,
  subject_user TEXT,
  subject_device TEXT,
  profile_id  TEXT,
  ip_prefix   TEXT,                             -- IPv4 /24 or IPv6 /48
  ua_family   TEXT,                             -- "Chrome 141 on macOS", no full UA string
  details     TEXT NOT NULL DEFAULT '{}'        -- JSON, never contents or secrets
) STRICT;
CREATE INDEX audit_user ON audit_events(actor_user, at);
CREATE INDEX audit_subject ON audit_events(subject_user, at);
CREATE INDEX audit_profile ON audit_events(profile_id, at);
CREATE INDEX audit_at ON audit_events(at);
```

Notes:

- `records_changes` is unique so that `change_seq` is a total order per profile. Accepted writes in a batch take `profiles.change_seq + 1 ... + n`, updated in the same D1 batch. D1 batches run as one transaction and D1 serializes writes per database, so no two batches interleave.
- Pull: `SELECT ... FROM records WHERE profile_id = ? AND change_seq > ? ORDER BY change_seq LIMIT ?`.
- Rekey batch: `SELECT ... FROM records WHERE profile_id = ? AND kv < ? AND (kv, id) > (?, ?) ORDER BY kv, id LIMIT ?` (row-value comparison, served by `records_kv`); `next_after` is an opaque encoding of the last row's `(kv, id)`. The first page omits the row-value condition. The API (11.12) and the flow (10.15) use the same `(kv, id)` order.
- `rotation_recommended` in API responses is computed as `writes_at_kv > 2^30` (4.1); every accepted `rotate_key` resets `writes_at_kv` to 0.
- `profiles.approvers` and `auto_approve` mirror the last `set_policy` entry so the server can filter `/v1/approvals`; clients rely only on the log.
- Rate limiting uses the Workers Rate Limiting binding; precise counters (email sends, code attempts) live in `email_logins`.
- Teamwerk needs no D1 tables. The Worker declares a Durable Object binding `PRESENCE_ROOM` (class `PresenceRoom`, SQLite-backed) in `wrangler.toml`, with a migration entry for the new class. The object's own storage holds only used ticket nonces with their expiry (18.5), so single use survives hibernation; it never holds presence data.
- Cron (daily): delete expired `webauthn_challenges`, `email_logins` (24 h after expiry), `setup_tokens`, `authorize_requests`, `oauth_codes`, `pairings`, `sessions`; delete expired `request_nonces`; hard-delete profiles past `purge_at`; delete audit events older than `AUDIT_DAYS`; delete revoked devices 90 days after `revoked_at` (rows that are still referenced by `profile_devices` with status `removed` keep only `id`, `user_id`, `kind`, public keys and `revoked_at`); inactivity warnings and deletions when enabled.

---

## 13. Logging and audit

### 13.1 Never logged, anywhere

The Worker MUST NOT write any of these to the audit table, `console.*`, Workers Logs, Logpush, tail workers, analytics or error reporting:

- record ciphertext, nonces, wraps, history blobs, meta ciphertext, recovery blobs (they belong in D1 tables only);
- logical keys or anything else from inside ciphertext (the server never has them);
- device tokens, token hashes, session ids, setup tokens, authorization codes, PKCE verifiers, pairing secrets, user codes, email codes, WebAuthn challenges and assertions;
- `Authorization`, `Cookie` and `EBS-Signature` header values, and request or response bodies.
- room tickets, the `Sec-WebSocket-Protocol` header, Teamwerk frames (member or control) and anything derived from their contents.

Implementation rule: the Worker logs through one function that accepts only a fixed set of fields (route template such as `/v1/profiles/:id/records`, status, duration, error code, request id). Route templates, not raw paths, are logged, so profile and record ids do not end up in operational logs. Uncaught exceptions are caught at the top level and logged with the error code and stack only. The self-hoster SHOULD leave Workers Logs at the default sampling and MUST NOT enable request header or body capture in Logpush.

Cloudflare's own edge logs and analytics see client IPs, timestamps, and URL paths. Paths contain ids but no secrets: all secrets travel in headers or bodies, and the dashboard puts link tokens in URL fragments.

### 13.2 Audit events

Each event stores the fields of the `audit_events` table. `details` holds only the listed keys.

| action | details |
|--------|---------|
| `auth.login` | `{ method: "passkey" \| "email" \| "setup" }` |
| `auth.login_failed` | `{ method, reason }` |
| `auth.passkey_added`, `auth.passkey_removed` | `{ passkey_name }` |
| `auth.passkey_counter_regression` | `{}` |
| `auth.email_login_changed` | `{ enabled }` |
| `auth.reauth` | `{ method }` |
| `device.connected` | `{ method: "oauth" \| "pairing", client_id, reconnect: boolean }` |
| `device.token_rotated` | `{}` |
| `device.code_replay` | `{ client_id }` |
| `device.revoked` | `{ by: "self" \| "dashboard" \| "admin" \| "replay" }` |
| `device.recovery_created`, `device.recovery_removed` | `{}` |
| `profile.created`, `profile.renamed`, `profile.deleted`, `profile.restored`, `profile.purged` | `{ label? }` (label only on created and renamed) |
| `grant.created`, `grant.revoked` | `{ role }` |
| `grant.approved` | `{ via, verified, devices: n }` |
| `grant.denied`, `grant.code_mismatch` | `{}` |
| `log.appended` | `{ types: [..], from_seq, to_seq }` |
| `key.rotated` | `{ kv }` |
| `rekey.completed` | `{ kv, records }` |
| `policy.changed` | `{ approvers, auto_approve }` |
| `export.account`, `export.profile` | `{}` |
| `account.created`, `account.disabled`, `account.deleted` | `{ by: "self" \| "admin" }` |
| `admin.user_created` | `{ delivery }` |

Record reads and writes are not audited individually (volume, and they would reveal activity patterns in more detail than needed). `profiles.change_seq` and `records.updated_by` already exist for sync.

Teamwerk is not audited: no event is written when a device connects to or leaves a room, so the server keeps no history of who was online when. Operational counters (open sockets per room, dropped frames) may be kept in memory or in aggregate Workers analytics without device or user ids.

### 13.3 Pseudonymization on deletion

When a user is deleted: events where they are actor or subject within their own account scope are deleted; events in other profiles' or the instance scope keep the event but set `actor_user` or `subject_user` to NULL and add `"deleted_user": true` to `details`. Device ids remain (pseudonymous, needed to interpret log entries).

---

## 14. Threat model

### 14.1 Assets

| Id | Asset | Why it matters |
|----|-------|----------------|
| A1 | Record plaintext (import groups, hidden lines, AI classifications, reminder mapping, preferences) | Business data; bank line references and classifications can contain personal data of third parties. |
| A2 | Profile keys (NK, DK of every version) | Give A1 and the record names. |
| A3 | Device private keys | Unwrap A2; sign log entries, wraps and requests. |
| A4 | Device tokens | API access as a device (only with A3, because of request signing). |
| A5 | Dashboard sessions, passkeys, email login | Account control: devices, grants, deletion. |
| A6 | Integrity of membership (the log) | Decides who gets A2. |
| A7 | Account metadata (emails, names, IP prefixes, device names) | Personal data of users. |
| A8 | Link between profile and administration number | Reveals which businesses a user works for. |
| A9 | Availability and integrity of synced data | Lost or corrupted shared state. |
| A10 | Recovery kit (paper) and recovery blob | Together give A3 of the recovery device. |

### 14.2 Actors

| Id | Actor | Capabilities assumed |
|----|-------|----------------------|
| T1 | Malicious server or operator (includes a compromised Cloudflare account, a malicious Worker deploy, Cloudflare itself) | Full read and write of D1, arbitrary API responses, can serve arbitrary dashboard code, sees all traffic content after TLS termination. Cannot change the extension code. |
| T2 | Malicious admin (dashboard role, when not also the operator, for example on a hosted instance) | Everything the admin API allows: create accounts, grant and revoke access, delete profiles, read metadata and audit. |
| T3 | Network attacker | Observes and modifies traffic between browser and Cloudflare; cannot break TLS. |
| T4 | Holder of a stolen device token | Has the token string, not the device's private keys. |
| T5 | Thief of an OAuth authorization code; redirect hijacker; malicious other extension | Can see or intercept a code or try to redirect it; can install an extension with another id. |
| T6 | Thief of an unlocked or locked laptop, or of a disk image | Has the Chrome profile files; with an unlocked session, can use the extension. |
| T7 | Malicious ex-member | Had legitimate access, kept local caches and old keys. |
| T8 | Malicious current member | Has DK and can write. |
| T9 | Attacker with XSS on the dashboard | Runs script in the dashboard origin in a victim's browser. |
| T10 | Compromised or hostile e-Boekhouden page | Runs script in the page's main world, controls the DOM that content scripts read, can `postMessage`. |
| T11 | Attacker who controls a user's mailbox | Can receive email login codes and set-up links. |
| T12 | Other users of the same instance | Have accounts; try enumeration and access to others' profiles. |
| T14 | Malicious member in Teamwerk | Is in the room with a valid device; can send any well-formed, correctly signed frame of their own, possibly from a modified client. |
| T15 | Traffic analyst | The operator or anyone who can see Teamwerk traffic patterns at the server. |

### 14.3 Threats and mitigations

#### T1: malicious server or operator

| Threat | Mitigation | Result |
|--------|------------|--------|
| Read record contents | AES-256-GCM under DK, which the server never has. | Prevented. |
| Learn record names | Record ids are HMAC under NK. | Prevented (but see T7 and Q2). |
| Learn the administration of a profile | Administration number only inside encrypted meta (7.3). | Prevented. |
| Forge or modify records | AEAD with associated data; `rid(k)` check. | Prevented. |
| Move records between profiles or ids, relabel versions or delete flags | All bound in the AAD (8.4). | Prevented. |
| Roll back a record to an older version | Clients refuse versions lower than seen (8.6). | Detected for records the client saw; a device that never saw the newer version cannot tell. |
| Withhold records or updates | Not preventable. | Residual (availability). |
| Add its own device or a fake member | Wraps must be signed by the author of the `add_device` entry, which must be an authorized member device (5.3, 9.4). A member approves only after a request shown with the locally computed device code. | Prevented when approvers compare codes; reduced to "trust the server" when they click without comparing, and fully when auto-approve is on (T13 below). |
| Substitute a requester's public key during approval | The approver signs the keys it displays; the device code is computed from those keys; the requester sees its own code. 100-bit codes are not grindable. | Detected when codes are compared. |
| Show a grantee a fake profile it controls | The grantee is shown the approver's device code (10.9 step 10) and can compare it. | Detected when compared; otherwise residual. |
| Give different members different logs (fork) | Hash chain and head gossip inside encrypted records (9.7). | Detected once a member reads a record written after the fork by the other side. |
| Hand different devices different DKs for one version | `dk_commit` and `nk_commit` in the signed log. | Detected. |
| Swap the recovery device in new profiles | Clients include only verifiable recovery devices (10.16). | Prevented. |
| Brute force the recovery blob | 128-bit recovery key. | Infeasible. |
| Serve malicious dashboard code | The dashboard has no keys. It can phish the user's login, approve pairings and grants server-side, but the cryptographic approval happens only in the extension. | Account-level actions possible (same as T2); data remains protected. |
| Trigger removals and rotations | Server can mark devices `revoking`. | Denial of service only. |
| Replay requests | Requests are signed with a timestamp; server is the party that would replay to itself. | Not relevant. |
| Learn metadata | See 14.4. | Residual by design. |

#### T2: malicious admin

| Threat | Mitigation | Result |
|--------|------------|--------|
| Grant themselves or an accomplice access to a profile | Grants are pending until a member device approves; the approval card shows who granted access ("toegang gegeven door <beheerder>"). | Prevented unless a member approves (social engineering) or auto-approve is on. |
| Create an account in a user's name and connect a device | Same: pending until approved; name and email are labelled as server-provided; the device code differs from the real user's device. | Prevented when codes are compared. |
| Revoke users, delete profiles | Server-side power by design. Profile deletion has a 7-day restore window and emails the owner; all actions are audited. | Denial of service, visible. Members keep local copies and can export. |
| Make themselves or others admin | `is_admin` follows `ADMIN_EMAILS` configuration only. | Requires operator access (then T1). |
| Read audit and metadata | By design. | Residual. |
| Cover tracks in the audit log | The admin cannot delete audit rows through the API. | An operator can (T1). |

#### T3: network attacker

TLS everywhere (HSTS on the dashboard; the client refuses `http:` except localhost in development builds). Even with a TLS break the attacker is at most T1 for the session, so data stays encrypted. Device requests are signed, so a captured token is useless without the key. OAuth uses PKCE and exact redirect URIs.

#### T4: stolen device token

- The token alone fails every request: each request needs a fresh ECDSA signature with the non-extractable device key (11.2).
- Tokens are stored hashed; a D1 leak does not reveal usable tokens.
- Tokens are never placed in URLs, `chrome.storage.local`, content scripts or logs (6.1, 13.1).
- Revocation is immediate from the dashboard or the extension.

#### T5: stolen OAuth code, redirect hijack, malicious extension

| Threat | Mitigation |
|--------|------------|
| Code intercepted in transit or from history | PKCE S256: the code is useless without the verifier, which never leaves the extension. Also `device_jkt` binding plus `device_proof`: the redeemer must hold the private key whose public key was approved. Code TTL 60 s, single use, replay revokes the device issued from it. |
| Redirect to an attacker-controlled URI | The server accepts only `https://<id>.chromiumapp.org/oauth` for ids on `ALLOWED_EXTENSION_IDS`, compared byte for byte; on failure it shows an error and never redirects. Chrome delivers `chromiumapp.org` redirects only to the extension with that id. |
| Malicious extension with another id starts the flow | Its id is not on the allow-list. Self-hosters MUST only add ids they build or trust. |
| Malicious extension on the allow-list (for example a stale development id) | Residual; operators keep the list minimal. |
| Attacker starts a flow and tricks the victim into approving (consent phishing) | The consent page shows device name and device code and warns to approve only a flow the user started. The attacker's code ends at the attacker's own extension, so the attacker gets an account device, not data: the device is pending in every profile until a member approves it with its (different) device code. |
| Mix-up between instances | `iss` parameter (RFC 9207) checked against the configured server. |
| CSRF on the consent decision | Session cookie `SameSite=Strict`; the form POST requires `Origin` equal to `ISSUER`, `Sec-Fetch-Site: same-origin` and a `csrf` field bound to the session and the `request_id` (11.2); the authorization parameters are bound server-side to `request_id`. |
| Pairing-code phishing (fallback) | The user code is typed, never in links; the page shows the device code; 10-minute expiry; attempt limits. Same outcome as above: a phished device still needs approval to see data. |

#### T6: stolen laptop

- Unlocked Chrome session: the thief can use the extension as that device, including decrypted data, until the device is revoked. Mitigation: revoke from the dashboard on another device (passkey on a phone) or from another extension; the server cuts access immediately; the next eligible member rotates the key.
- Locked laptop or disk image: Chrome profile files contain the IndexedDB with keys and cached plaintext unencrypted. Protection relies on OS disk encryption. Residual risk; see Q6 for an optional app lock.
- The device token without the profile's IndexedDB is useless (T4).

#### T7: malicious ex-member

| Threat | Mitigation | Result |
|--------|------------|--------|
| Read new data after removal | Rotation; no wrap for removed devices; history chain only goes backward. | Prevented. |
| Read old data | They had it. Lazy re-encryption limits exposure if they later obtain a database dump together with their old DK. | Residual (inherent). |
| Continue to use the API | Server-side revocation is immediate; the device is removed in the log. | Prevented. |
| Map record ids to names with server help | NK is not rotated in v1, so an ex-member colluding with the server can compute `rid` for names they can guess and watch which records change. | Residual, metadata only (Q2). |
| Read records written between revocation and rotation | Only with server collusion; rotation happens at the next sync of any eligible member device. | Small residual window. |
| Read new writes of a member whom the server keeps stale | A server colluding with the ex-member can withhold the rotation from one honest member (and accept that member's writes under the old `kv`, which an honest server refuses). The ex-member then reads those writes. Detection: readers' stale writer check (8.6), the writer's own checks before pushing (10.13 step 3.5), log heads in records and in Teamwerk `hello` and `st` frames (9.7, 18.8), and comparing the ledenlijstcode. | Not prevented. Detected quickly in profiles where members write or are online together; detection can take long in a quiet profile, until the 14-day notice or a manual code comparison. |

#### T8: malicious current member

Members are trusted with the data. A member can read everything, overwrite or delete records (LWW), approve others (unless `approvers = owner`), and remove other members' devices only after server-side revocation. Records carry the writer's device id inside the ciphertext and the server's `updated_by`, so abuse is attributable. Residual: data destruction by a member; mitigated by local copies on other devices and exports.

#### T9: XSS on the dashboard

- Prevention: strict CSP on all dashboard pages: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'`. The OAuth consent page adds the single validated redirect origin (`https://<client_id>.chromiumapp.org`) to `form-action`, because Chrome applies `form-action` to redirects after a form submission. No third-party scripts, no inline scripts, no `innerHTML` with server data; all user-controlled strings (names, labels, device names, emails) are rendered as text. These strings come from other users and are the main stored-XSS vector.
- Containment: the dashboard holds no keys. A script with the victim's session can do what the victim can do server-side, but sensitive actions need a fresh user-verified passkey ceremony (`session+reauth`), which a script cannot complete without the user tapping the authenticator. Data access still needs a cryptographic approval in an extension.
- Session cookies are `HttpOnly`, so they cannot be exfiltrated.

#### T10: compromised e-Boekhouden page

| Threat | Mitigation |
|--------|------------|
| Page script calls the extension | No `externally_connectable` entry for e-Boekhouden origins; the page cannot use `chrome.runtime` to reach the extension. |
| Page sends `window.postMessage` to content scripts | Content scripts do not accept sync or store commands from window messages. |
| Page steers content-script input (DOM) | Content scripts may only call the narrow store API (15.2). The service worker validates sender (`sender.id == chrome.runtime.id`, tab URL on `*.e-boekhouden.nl`), namespace, key format, value schema and size, and rate limits writes per tab. |
| Read keys or tokens | Never present in content scripts or the page (6.1). IndexedDB of the extension origin is not reachable from the page origin. |
| Read decrypted data shown in the page | Inherent: the extension renders it into the page DOM. Only data of the active profile for that administration is ever sent to that tab. |
| Lie about the administration number to read another profile | The service worker only returns profiles indexed for the reported administration; the user has access to those anyway in e-Boekhouden. A hostile page could cause the extension to display data of another accessible administration inside it. Residual, low. |
| Write garbage that propagates to colleagues | Schema validation and size limits per namespace; per-tab write rate limits; LWW history is not kept, so destruction is possible. Residual; local copies on other devices until they sync. |
| Trigger request floods | Store writes are debounced and batched; the server rate limits per device. |

#### T11: mailbox takeover

Email login codes and set-up links give account access. Mitigations: users with passkeys can disable email login; admins are urged to; email login codes are short-lived and attempt-limited. Account access alone does not give data access: new devices need cryptographic approval by a member, who sees the device code. Residual: an attacker with mailbox access can social-engineer an approval, revoke devices or delete the account.

#### T12: other instance users

- `GET` endpoints only return resources the caller is authorized for; unknown and forbidden resources both return `404` to avoid probing.
- Email start always answers `202`; discoverable passkeys need no username; the admin API is admin-only.
- Ids are 128-bit random.
- Rate limits and quotas per user and device (11.4).

#### T13: automatic approval enabled

When the owner enables `auto_approve`, any device the server lists as pending is approved by the next member device online. The server, the operator and any admin can then obtain the profile keys by creating or granting an account. End-to-end encryption still protects against database dumps and network attackers, but no longer against T1 and T2. The client states this when enabling (10.11), the log records `via: "auto"`, and the members list marks such devices.

#### T14: malicious member in Teamwerk

| Threat | Mitigation | Result |
|--------|------------|--------|
| Show fake cursors or "bezig" markers under another member's name | Every frame is signed with the sender's device key; receivers attribute it to the device in the header only after verifying against the verified log, and render the user's log name (18.10). The server also drops frames whose header device differs from the socket's device. | Prevented. |
| Spoof a name by choosing a misleading display name | Names in the log are attested by the approver (`user_name`) or set by the user (`set_name`, auditable in the log); avatars use colors from `user_id`. | Reduced; a member can still pick a confusing name for themselves. |
| Flood with own cursors or markers (UI noise, discouraging colleagues from opening rows) | Client and server rate limits, muting per colleague, markers are soft and attributable. | Annoyance only. |
| Lure a colleague to another page via "Volg" | Follow paths are validated against per-route patterns and allow-listed parameters, navigate only within the follower's own e-Boekhouden origin, and only on the follower's click. | Prevented beyond navigation to a normal e-Boekhouden page. |
| Leak or inject page content through payloads | Strict validator on send and receive; no free text fields except the bounded, validated route id and follow path. | Prevented. |
| Watch silently | Unmodified clients always announce themselves; a modified silent client still appears as "verbonden" from the server's socket list, mapped to its log name. | Visible unless the server colludes. |

#### T15: replay and traffic analysis in Teamwerk

- Replay: per-session sequence numbers, a 120-second timestamp window, session ordering, and binding of profile, key version and sender in the associated data and signature (18.15). A server replaying old frames is detected and the frames are dropped.
- Traffic analysis: the server sees who is connected, when, for how long, and the timing and count of frames per socket. Payloads are padded to fixed sizes (256, 512 or 1,024 bytes), so frame types are mostly indistinguishable by length, but cursor bursts reveal when someone moves the mouse, and co-presence reveals who works together when. Cover traffic is not used, because constant-rate frames would cost battery and Durable Object requests for a modest gain. Residual.

#### Teamwerk additions to other actors

- T1 (malicious server): cannot read or forge presence; can drop, delay or withhold frames, lie in `present`, `join` and `leave` hints (devices not active in the log are ignored), and keep sockets of removed devices open (useless to them after the rotation). It learns the metadata above.
- T10 (hostile page): cannot open the socket or reach the port (only the extension's content script can); cannot read the closed shadow root, but can observe layout and may infer where overlay elements are drawn. It can make the local content script report wrong anchors, which only misplaces the local user's own cursor for others.
- T12 and DoS: room cap, ticket rate limit, per-connection frame limits, frame size cap, one socket per device per room, three rooms per device, `Origin` check on upgrade, and client-side pre-verification rate limiting bound the cost of an abusive member or device. Cloudflare's network-level DDoS protection covers unauthenticated floods.

### 14.4 Metadata the server necessarily learns

| Metadata | Detail |
|----------|--------|
| Accounts | Email, display name, admin flag, creation and last login time. |
| Devices | Name, platform, extension id, public keys, connection time, last seen (hour granularity), token age. |
| Social graph | Which users share which profiles, roles, who granted and who approved, whether codes were compared (`verified`). |
| Profiles | Count per user, label, member count, key version history (rotations imply removals), policy. |
| Records | Count per profile; ciphertext size bucket (8.3); stable opaque id per logical key; version number per record (how often it changed); which device wrote it and when; tombstones and their time. |
| Timing | When each device syncs. Sync on screen open reveals working hours and how often screens are opened (not which screen). Writes reveal editing activity bursts. |
| Network | IP addresses at request time (Cloudflare and the Worker); only a prefix is stored in the audit log. |
| Plaintext labels | Profile labels, device names, user display names and emails in the server's own tables (names inside membership logs are encrypted, 9.3). |
| Approvals | Who granted, who approved, whether the approver ticked the code comparison (`verified`), denials and code mismatches. |
| Recovery and keys | Whether a user has a recovery kit and when it was made; rotation times and reasons; during re-encryption, which records were not changed since the last rotation. |
| Teamwerk | Which devices are connected to which profile's room, from when to when (only while a tab is visible), number of people online together, frame counts and timing per socket (mouse activity), frame size class. Not route, cursor, focus or status contents, and no history is stored. |
| Inferences | Two profiles edited in lockstep by the same devices are probably related; a rotation right after a grant revocation identifies who was removed. |

The server does not learn record contents, logical keys, administration numbers or names, values of preferences, display names inside logs, Teamwerk routes, cursors, focus or status, or the plaintext of profile meta. It does learn from timing alone when a user has e-Boekhouden open: sync requests follow screen opens (at most one per profile per 60 s) and Teamwerk connections exist exactly while a tab is visible. From this it can approximate working hours, how often screens are opened and who works at the same time, though not which screen.

### 14.5 Residual risks (summary)

1. Users who click "Toestaan" without comparing device codes trust the server's identity assertions for that approval.
2. Auto-approve profiles trust the server and admins completely.
3. Forks between members who never write are not detected.
4. Rollback to an older version is not detected by a device that never saw the newer one; withholding data is never preventable.
5. Ex-members keep what they had; with server help they can map guessable names to record ids (NK not rotated).
6. Plaintext caches and keys on disk are protected only by OS disk encryption.
7. A hostile e-Boekhouden page can read whatever the extension shows in it and can write garbage into the active profile within validation limits.
8. The operator learns the metadata in 14.4.
9. Account-level attacks (mailbox takeover, phished passkey ceremonies, malicious admin) can cause denial of service and deletion (7-day restore window for profiles; none for account deletion by an admin, apart from D1 Time Travel).
10. A malicious extension build (supply chain of the extension itself) defeats everything; it is outside this protocol.
11. Teamwerk reveals online times, co-presence and activity timing to the operator, and the overlay's layout to a hostile page.
12. A member can choose a confusing display name for themselves and can add noise to colleagues' screens within rate limits.
13. A server colluding with a removed member can keep one honest member stale by withholding a rotation, exposing that member's new writes to the removed member until the stale writer is detected (14.3 T7). Detection is fast in active profiles and slow in quiet ones.

---

## 15. Client integration notes

### 15.1 Manifest changes

```json
{
  "permissions": ["cookies", "storage", "alarms"],
  "optional_permissions": ["identity"],
  "optional_host_permissions": ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"]
}
```

- `identity` is needed for `chrome.identity.launchWebAuthFlow` and `getRedirectURL`. It does not grant access to the user's Google identity (that is `identity.email`, which is not requested). It is an optional permission, requested together with the server's host permission in the "Verbinden" click (10.4 step 2). Optional permissions never trigger a re-approval prompt or disable the extension on update, so existing users are unaffected whatever warning Chrome attaches to it, and users who never enable sync never grant it. The pairing code fallback (10.5) does not need it.
- `alarms` is used only for one-shot retry backoff (10.13), never for periodic polling.
- The host permission for the configured server is requested at configuration time (10.4 step 2) with `chrome.permissions.request({origins: ["https://sync.example.nl/*"]})`, inside a click handler on an extension page. A hosted default instance MAY instead be listed in `host_permissions` in a later version. Localhost entries are for development builds only and SHOULD be stripped from store builds.
- No `externally_connectable`. The extension never exposes sync to web pages.
- `minimum_chrome_version` stays at 116 (IndexedDB and Web Locks in service workers, `chrome.storage.session`, P-256 WebCrypto are all available).
- Teamwerk needs no new permissions: the WebSocket is opened by the service worker (WebSockets are not governed by host permissions or CORS, which is why the server checks `Origin`), and no `offscreen` permission is used (18.3).

### 15.2 Process boundaries

| Context | May | May not |
|---------|-----|---------|
| Service worker | Everything: keys, tokens, API calls, crypto, sync engine, store backends, message handlers. | |
| Options page (tab) | Connect flow (permission request, `launchWebAuthFlow`), recovery kit creation and recovery, export, device and member management. It calls into the service worker for crypto and API work, or uses the same modules directly; it may hold raw key bytes transiently during recovery. | |
| Popup | Status, profile switch, approvals ("Toestaan", "Weigeren"), "Nu synchroniseren", pending notices. Approvals run in the service worker. | Run `launchWebAuthFlow` (it closes on focus loss). |
| Content scripts | `store.get/set/delete/list` for allowed namespaces through `chrome.runtime.sendMessage`; report administration number and screen opens; render navbar profile menu and approval cards from data the service worker sends (labels, names, device codes). Clicks in the navbar menu send `profile:select`, `approval:open` (opens the popup or options page for the actual decision) and `sync:now`. | Receive keys, tokens, wraps, ciphertext, record ids or data from other administrations. Approve or deny access directly (a hostile page could fake clicks inside the page; decisions happen in extension UI). |
| Content scripts (Teamwerk) | Report visibility, route id and follow path, pointer anchor and offset, row keys of rendered rows, and open rows through the `teamwerk` port; render the overlay and avatars from decrypted, validated events. | Hold `K_pres`, `K_focus` or the socket; see other members' follow paths; build payload JSON. |
| Page main world | Nothing. | Everything. |

Message handlers in the service worker MUST check `sender.id === chrome.runtime.id`, and for content-script messages `sender.tab` and `sender.url` against `https://*.e-boekhouden.nl/*`, and `sender.frameId` where relevant.

Note on the navbar approval card: the request mentions one-click "Toestaan" in the navbar menu. Because a hostile page can synthesize clicks on elements inside the page DOM (including a closed shadow root), the navbar card shows the request and the device code, and its "Toestaan" button opens the extension popup or an extension page where the actual one-click approval happens. This keeps it to one click for the user while the decision runs in a context the page cannot drive.

### 15.3 Storage abstraction

Features use one interface, independent of the backend:

```ts
interface Store {
  get(key: string): Promise<unknown | undefined>
  set(key: string, value: unknown): Promise<void>
  delete(key: string): Promise<void>
  list(prefix: string): Promise<Array<{ key: string, value: unknown }>>
  onChanged(listener: (changes: Array<{ key: string, value: unknown | undefined, source: "local" | "remote" }>) => void): () => void
}
```

- Keys are logical keys (8.1), scoped implicitly by the current administration and, for the `sync` backend, the active profile.
- Each namespace is configured with one backend:
  - `local`: today's behaviour, `chrome.storage.local` (or IndexedDB) on this device only, keyed by administration.
  - `opmerking`: optional; writes tags into e-Boekhouden's own comment field of the object (for example a bank line). Visible to everyone with access to that administration in e-Boekhouden and to e-Boekhouden itself; not encrypted; subject to that field's length limits; useful for data that should live with the bookkeeping. The backend parses and writes a delimited tag block and leaves the rest of the comment untouched.
  - `sync`: this protocol. Reads from the local plaintext cache (IndexedDB `records`), writes to cache plus outbox, sync per 10.13. `list(prefix)` is answered from the cache by logical key, which is why logical keys are stored inside the ciphertext.
- Switching a namespace's backend migrates data with an explicit user action ("Gegevens naar synchronisatie verplaatsen"), never silently.
- `onChanged` fires with `source: "remote"` after a pull applies changes, so features update open screens.
- Values MUST be JSON serializable, at most 65,532 bytes serialized including the payload wrapper (8.3); the store rejects larger values.
- Each namespace registers a validator (schema and size); the service worker applies it to writes from content scripts before they reach the cache.

### 15.4 Administration and profile context

- The content script detects the administration number from the e-Boekhouden page (the existing session switcher already knows the active administration) and sends `{type: "context:administration", administration}` on navigation.
- The service worker keeps, per tab, the administration and the active profile, and answers store calls in that context. A tab without a detected administration gets only the `local` backend.
- `activeProfileByAdministration` is stored in IndexedDB on the device (7.4).

### 15.5 UI texts (Dutch, normative meaning, wording may be refined)

| Situation | Text |
|-----------|------|
| Connect button | Verbinden |
| Manual sync | Nu synchroniseren |
| Waiting for approval | Wacht op goedkeuring door <naam> |
| Approval card | <naam> wil toegang tot <profiel> |
| Approve, deny | Toestaan, Weigeren |
| Compare box | Ik heb de code vergeleken |
| Mismatch | Codes komen niet overeen |
| Approved notice | Toegang tot <profiel> goedgekeurd door <naam> |
| Offline | Niet gesynchroniseerd (<n> wijzigingen wachten) |
| Security warning | Beveiligingswaarschuwing: ... (log invalid, fork, rollback, wrap invalid) |
| Default profile name | Mijn profiel |
| Recovery | Herstelsleutel maken, Herstellen met herstelsleutel |

### 15.6 Implementation checklist for the client

1. IndexedDB schema `ebs-sync` v1 with stores `device`, `profiles`, `keys`, `records`, `outbox`, `meta` (hybrid clock, cursors, active profiles).
2. Crypto module with exactly the functions of sections 3 to 5; unit tests against Appendix A.
3. Log verifier as a pure function `(state, entry) -> state | error`.
4. Sync engine per 10.13 with Web Locks.
5. Store backends and message API per 15.2 and 15.3.
6. UI: options page (connect, devices, profiles, members, recovery, export), popup (status, switch, approvals), navbar menu (switch, sync, approval notice).
7. Teamwerk module per 18 and 15.7: socket manager, frame codec, validator, overlay.

### 15.7 Teamwerk client notes

- **Port protocol.** Each top-frame content script opens `chrome.runtime.connect({name: "teamwerk"})` when Teamwerk is enabled. Messages from the content script: `tw:visibility {visible}`, `tw:route {id, follow?}`, `tw:cursor {a, x, y, v?} | null`, `tw:rows {rowkeys}` (answered with `{refs: {rowkey: ref}}`), `tw:focus {rowkeys, m} | null`, `tw:pause {paused}`, `tw:follow {user_id}`. Messages to the content script: `tw:room {members: [{user_id, name, color, status, route_label, followable, is_me}]}`, `tw:cursor {user_id, a, x, y, v?} | {user_id, gone: true}`, `tw:focus {user_id, refs, m} | {user_id, gone: true}`, `tw:overlap {user_id, refs}`. The service worker sends cursors only to tabs whose route id matches, and only data of the tab's own profile.
- **Input capture.** `pointermove` listeners are passive; positions are coalesced in `requestAnimationFrame` and sent at most every 66 ms; nothing is sent while the pointer is still. Idle is 60 seconds without pointer or keyboard input (keyboard events are counted, never read).
- **Route ids.** The extension ships a table of e-Boekhouden URL patterns to route ids, Dutch labels, a `followable` flag and the allowed query parameters per route. Unknown pages map to `other` and are not followable.
- **Validation.** The same validator module (18.8) runs on outgoing and incoming payloads in the service worker. Unit tests MUST cover rejection of text-bearing anchors, oversize strings, extra keys and follow paths with schemes, `//`, backslashes or disallowed parameters.
- **Performance.** Verification is asynchronous WebCrypto; incoming frames are processed in order per sender, dropped beyond 20 per second per sender before verification; the overlay redraws at most once per animation frame.
- **Lifecycle.** The socket opens only while a tab for the profile is visible (18.4) and heartbeats keep the service worker alive while it is open; when no tab is visible the worker may sleep, which is intended.
- **Settings.** `teamwerk.enabled` (the "Teamwerk" setting), `teamwerk.paused`, `teamwerk.muted` (user ids) in IndexedDB `meta`.

---

## 16. GDPR

This section gives orientation for self-hosters and a future hosted instance. It is not legal advice.

### 16.1 Roles

- Self-hosting for one's own organization: the organization is the controller for account data (users, devices, audit) and for the synced bookkeeping-related data.
- Hosted instance for customers: each customer organization is the controller for its users' synced data; the hosting party is a processor (Art. 28 GDPR) and needs a data processing agreement with each customer, listing Cloudflare (Workers, D1) and the email provider as sub-processors. For account and security data it is reasonable for the hosting party to act as controller for its own service operation; this must be stated in the privacy notice.
- Ciphertext: the synced data can contain personal data of third parties (names on bank lines, debtor references). For the operator, who has no keys, the ciphertext is pseudonymized at least. The CJEU judgment in EDPS v SRB (case C-413/23 P, 2025) supports the view that pseudonymized data need not be personal data for a recipient who cannot re-identify, but operators SHOULD NOT rely on this and SHOULD apply GDPR security and processor obligations to ciphertext anyway. Self-hosters should verify the current interpretation with counsel.

### 16.2 Lawful basis (notes per category)

| Data | Typical basis |
|------|---------------|
| Account email and name, passkeys, devices, grants | Art. 6(1)(b), performance of the contract (hosted), or Art. 6(1)(f), legitimate interest of the employer in providing work tools (self-hosted within an organization; mind the employment context). |
| Audit events with IP prefix and user agent family | Art. 6(1)(f), legitimate interest in security and abuse prevention (Recital 49). Data minimized: prefix only, family only. |
| Session cookie | Strictly necessary for the service the user requested; exempt from consent under the ePrivacy rules (Dutch Telecommunicatiewet art. 11.7a). No analytics or tracking cookies are used, so no cookie banner is needed. |
| Login and notification emails | Art. 6(1)(b) or (f), as for the account. |
| Teamwerk presence | Processed only in transit, never stored, and only for users who switched on the extension setting "Teamwerk". Art. 6(1)(f), legitimate interest in working together. Organisations that use Teamwerk should check it against their own rules on monitoring at work. |
| Synced profile data | Processed on behalf of the controller (the organization using e-Boekhouden), whose own basis applies. This data is auxiliary to the official administration in e-Boekhouden; it is not itself the fiscal administration, so the 7-year fiscal retention obligation does not apply to it and users can delete it freely. |

### 16.3 Retention

| Data | Retention |
|------|-----------|
| WebAuthn challenges | 5 minutes, purged daily |
| Email login requests (they contain the email address, also for unknown addresses) | 15 minutes validity, purged 24 hours after expiry |
| Request nonces | 10 minutes, purged daily and on lookup |
| Teamwerk ticket nonces (Durable Object storage) | until the ticket expires plus 2 minutes, deleted by the object's alarm |
| Set-up tokens | 72 hours validity, purged after expiry |
| Authorization requests and codes | 10 minutes and 60 seconds validity, purged daily |
| Pairings | 10 minutes validity, purged daily |
| Sessions | 30 minutes idle, 12 hours absolute, purged daily |
| Device tokens | rotated every 30 days, expire after 180 days of inactivity |
| Revoked devices | metadata deleted 90 days after revocation, except public keys and ids still referenced by membership logs |
| Records | until deleted by a user; tombstones for the life of the profile (8.8) |
| Grants with status `denied` or `revoked` | until a re-grant, profile deletion or account deletion; needed to show history to owners and to re-grant |
| Disabled accounts | until an admin deletes them or the inactivity rule applies |
| Email provider and Cloudflare logs | outside the Worker; the self-hoster configures the email provider's retention and does not enable Cloudflare log products that store request details beyond their defaults (13.1) |
| Deleted profiles | 7 days restore window, then hard-deleted |
| Membership logs, wraps, history | lifetime of the profile; history and old wraps deleted after re-encryption completes |
| Audit events | 365 days (configurable) |
| Accounts | until deleted; optional automatic deletion after configurable inactivity with 30 days' warning |
| D1 Time Travel (point-in-time restore) | up to 30 days, maintained by Cloudflare; deleted data disappears from it after that window. Documented in the privacy notice. |
| Teamwerk presence | Not stored. Exists in transit and in Durable Object memory only for the duration of a connection; cleared when the socket closes. Not included in exports because nothing is held. |

### 16.4 Export formats

Server export (`application/x-ndjson`, one JSON object per line, UTF-8):

```
{"type":"export_header","format":"ebs-server-export","version":1,"scope":"account","user_id":"u_..","issuer":"https://..","exported_at":1793270400123}
{"type":"user","data":{ User fields, status, created_at, last_login_at }}
{"type":"passkey","data":{ Passkey fields, aaguid, transports, public_key_cose_b64u }}
{"type":"device","data":{ Device fields }}
{"type":"session","data":{ created_at, last_seen_at, expires_at, ua_family }}
{"type":"recovery_kit","data":{ RecoveryKit }}
{"type":"grant","data":{ profile_id, role, status, granted_by, granted_at }}
{"type":"profile","data":{ profile_id, label, owner_id, created_at, current_kv, meta: Meta }}
{"type":"log_entry","profile_id":"p_..","data":{ LogEntry }}
{"type":"wrap","profile_id":"p_..","data":{ Wrap }}                 // wraps addressed to the user's devices
{"type":"history","profile_id":"p_..","data":{ History }}
{"type":"record","profile_id":"p_..","data":{ StoredEnvelope }}
{"type":"audit_event","data":{ audit event as in 11.13 }}
{"type":"export_footer","lines":1234,"sha256":"<b64u hash of all previous lines including newlines>"}
```

- Account scope includes every profile the user can access. Profile scope (`GET /v1/profiles/{id}/export`) has `"scope":"profile"` and contains the profile, its members (`{"type":"member", ...}` with id, name, email, role, status, as visible in the app to members), the log, the caller's wraps, history and records.
- Excluded on purpose: token hashes, session id hashes, code and challenge hashes, other users' wraps. They are security credentials or derived values that would weaken security if the export file leaks, and they carry no information about the person beyond what is exported (the existence and timing of each token are exported in the device rows).
- With the extension and the user's device keys, the server export is decryptable; without them it is ciphertext. That is the point of E2EE.

Extension export (decrypted, `application/json`, file `eb-sessions-export-<date>.json`):

```json
{
  "format": "eb-sessions-export",
  "version": 1,
  "exported_at": "2026-10-29T10:00:00Z",
  "server": "https://sync.example.nl",
  "user": { "id": "u_...", "email": "jan@example.nl" },
  "device": { "id": "d_...", "name": "Chrome op MacBook" },
  "profiles": [
    {
      "profile_id": "p_...",
      "label": "Mijn profiel",
      "role": "owner",
      "administration": { "number": "123456", "name": "Voorbeeld BV" },
      "members": [ { "user_id": "u_...", "name": "Jan", "email": "jan@example.nl", "role": "owner" } ],
      "records": [
        { "key": "hiddenLines/8812345", "value": { "hidden": true }, "version": 3, "updated_at": 1793270400123, "updated_by_device": "d_..." }
      ],
      "tombstones": [ { "key": "ai/8812000", "version": 5, "deleted_at": 1793270000000 } ]
    }
  ],
  "local": { "namespaces": { } }
}
```

- "Exporteer profiel" produces the same document with one profile; "Exporteer alles" with all accessible profiles and, optionally, the `local` backend data.
- The extension runs a full sync first and warns if records failed to decrypt.
- The file is plaintext; the extension says so before saving.

### 16.5 Deletion semantics

| Action | Effect on server | Effect on devices |
|--------|------------------|-------------------|
| Delete a record | Tombstone (encrypted), kept for the life of the profile so that devices that were offline learn of the deletion | Removed from caches at the next sync of each device |
| Revoke a device | Immediate access stop; metadata purged after 90 days | Revoked device keeps its local cache; the extension deletes a profile's sync data when its own removal appears in the verified log, or when the user confirms |
| Leave or remove a member | Grant revoked; removal and rotation in the log | As above for the member's devices |
| Delete a profile | 7 days restorable, then hard delete of all profile data | Users are asked before local copies are deleted |
| Delete the account | Immediate hard delete of account data, owned profiles, devices, sessions, passkeys, recovery kit; pseudonymized audit; log entries kept in shared profiles with pseudonymous ids, public keys and the encrypted display name only (needed for chain verification; 9.3) | The extension wipes sync data after offering an export |
| Backups | D1 Time Travel keeps deleted data up to 30 days; restores of older points are an operator action and must re-apply deletions | n/a |

Data other members already synced to their devices cannot be deleted remotely; this is inherent to sharing and is stated in the privacy notice.

### 16.6 Requests from third parties

Persons mentioned in bookkeeping data direct their requests to the controller (the organization). The operator cannot search or read ciphertext and forwards such requests. The controller handles them in e-Boekhouden and, for auxiliary data, through the extension (find, export, delete records).

### 16.7 Breaches

A D1 leak exposes account metadata (emails, names, device names, IP prefixes in audit), which may require notification under Art. 33. Synced data is encrypted with keys that are not on the server, so notification to data subjects is not required for it under Art. 34(3)(a), provided device keys were not compromised.

---

## 17. Open questions

Only questions that need a decision by the product owner are listed. Engineering choices are made in the sections above.

| Id | Question | Current default in this spec |
|----|----------|------------------------------|
| Q1 | Should per-screen preferences be personal instead of shared within a profile? | Shared per profile. Alternative: a personal single-member profile per user and administration, or a `private/` namespace with a per-user key. |
| Q2 | Rotate NK on member removal (give every record a new id) so that ex-members cannot map guessable names to ids with server help? | No: it rewrites every record id and tombstones the old ones on each removal. |
| Q3 | Should the default profile label include the administration name for convenience, accepting that the server learns it? | No, `Mijn profiel`. |
| Q4 | Default approver policy: any member, or the owner only? | Any member; the owner may restrict it. |
| Q5 | May owners create accounts when sharing (`OWNERS_CAN_INVITE`)? | `false`. |
| Q6 | An optional app lock (local cache and device keys protected by a passphrase or the WebAuthn PRF extension) against a stolen, locked laptop or a disk image? | Not in v1. |
| Q7 | A flow for changing a user's email address while keeping `user_id`? | Not in v1; an admin recreates the account. |
| Q8 | Faster approvals through Web Push or a Durable Object channel, instead of "at the next sync" plus an optional email? | Next sync plus optional email. |
| Q9 | A hosted instance: DPA template, data location, abuse handling, pricing. | Out of scope for v1. |
| Q10 | How the `opmerking` and `sync` backends interact for the same namespace (both writing, migration, conflicts). | One backend per namespace; explicit migration only. |
| Q11 | When a sole owner of shared profiles deletes their account, transfer ownership automatically to the longest-standing member? | Block with `409` and require transfer or deletion. |
| Q12 | A read-only member role? | Not in v1. |
| Q13 | Encrypt the extension's plaintext export file, for example under a one-time passphrase? | Plaintext with a warning. |
| Q14 | A continuous "volgen" mode in Teamwerk that keeps following a colleague's navigation? | One-shot "Volg" only. |

---

## 18. Teamwerk (live presence)

### 18.1 Purpose and scope

Teamwerk shows members of the same profile who are online at the same time:

- which e-Boekhouden page each is on, as avatars in the navbar ("Dion · Importeren") with "Volg" to open the same page;
- live cursors with name labels when two members are on the same page;
- "bezig" markers on the row or record a colleague has open, and a soft warning when two people open the same one. Teamwerk never locks anything and never blocks saving.

Teamwerk is a plain extension setting, "Teamwerk", off by default. It can be paused at any moment and shows everyone who is in the room. Presence is end-to-end encrypted, relayed by the server without storage, and exists only while the user has an e-Boekhouden tab visible.

### 18.2 Architecture

```
 e-Boekhouden tab (visible)                    Cloudflare
 +-----------------------------+               +------------------------------------------+
 | page JS (untrusted)         |               | Worker                                   |
 | content script              |               |  POST /v1/profiles/{id}/presence/ticket  |
 |  - reads anchors, rows,     |               |  GET  /v1/presence/ws  (upgrade)         |
 |    route, pointer, focus    |               |        | validates ticket, forwards      |
 |  - shadow-DOM overlay       |               |        v                                 |
 |    (cursors, markers)       |               | Durable Object PresenceRoom              |
 +------------+----------------+               |  one per profile (idFromName(profile_id))|
              | runtime port "teamwerk"        |  WebSocket Hibernation API               |
              | (plain events, no keys)        |  relays opaque binary frames,            |
 +------------v----------------+   WSS         |  no storage, rate limits, room cap       |
 | service worker              +-------------->|                                          |
 |  - one socket per profile   |  signed,      +------------------------------------------+
 |  - K_pres, signing, verify  |  encrypted
 |  - names from verified log  |  frames
 +-----------------------------+
```

### 18.3 Where the socket lives: service worker

The WebSocket lives in the extension service worker. Reasons:

1. Chrome 116 (the extension's minimum version) keeps a service worker alive while it exchanges WebSocket messages at least every 30 seconds. Teamwerk sends a heartbeat every 20 seconds while connected, so the worker stays alive exactly as long as the socket is needed and can sleep as soon as it closes.
2. The service worker already holds the device keys and the verified membership logs, so presence keys, frame signing and verification stay in the one context that holds secrets (6.1).
3. An offscreen document would need a declared `reason`; none of the offscreen reasons covers network sockets, so using one would be a policy risk in the Chrome Web Store review. It would also be a second context holding key material, with an extra messaging hop.

The socket is never opened from a content script or the page.

### 18.4 Connection lifecycle

1. **When to connect.** The service worker tracks, per tab, the profile in use and `document.visibilityState` (reported by the top-frame content script on load and on every `visibilitychange`). It opens a socket for a profile when both hold: the setting "Teamwerk" is on, and at least one e-Boekhouden tab using that profile is visible. Content scripts in sub-frames (`all_frames: true`) do not take part.
2. **When to disconnect.** 30 seconds after the last visible tab for that profile becomes hidden or closes (a grace period so tab switches do not cause reconnect storms). The client sends a `bye` frame, then closes with code 1000.
   **Between pages.** Navigating from one e-Boekhouden page to the next unloads the content script, which closes its port. The service worker does not treat a closed port as a hidden tab: it keeps the tab's last state for the same 30-second grace period, keeps the socket open, and keeps sending heartbeats, which also keep the worker itself alive (Chrome 116 and later extend the worker's lifetime while WebSocket messages flow at least every 30 seconds). The new page's content script reconnects the port within a second or two and reports visibility and route, so a navigation causes no reconnect of the socket. The local cursor is sent as `cu: null` when the port closes, and route and focus are refreshed by the new page.
3. **Limits per device.** At most one socket per profile and at most 3 sockets in total. When several tabs of one profile are visible, the tab with the most recent user input provides route, cursor and focus.
4. **Ticket.** `POST /v1/profiles/{id}/presence/ticket` (device auth, 18.5). Tickets are valid 60 seconds and single use.
5. **Connect.** `new WebSocket(ws_url, ["ebs.v1", "ebs.ticket." + ticket])`. The ticket travels in the `Sec-WebSocket-Protocol` header, not the URL, so it does not appear in URL logs. The server selects `ebs.v1`.
6. **Welcome.** The room sends a `welcome` control frame listing the connected devices. The client sends a `hello` frame (status, route, focus) and starts heartbeats.
7. **Heartbeats.** The client sends the text frame `ping` every 20 seconds. The Durable Object answers `pong` through `setWebSocketAutoResponse`, which does not wake a hibernated object. If no `pong` arrives within 10 seconds, the client closes and reconnects. The room closes sockets whose last auto-response is older than 60 seconds (checked with an alarm every 60 seconds while sockets exist).
8. **Presence keepalive.** Every 30 seconds, and on every change, the client sends a `st` (status) frame. A member is shown as present only while verified frames keep arriving; without one for 75 seconds the member is shown as gone, even if the server still lists the socket.
9. **Maximum age.** The room closes every socket after 1 hour with code 4000. The client reconnects at once with a new ticket. This re-checks membership in D1 at least hourly in addition to the explicit kicks of 18.13.
10. **Reconnect and backoff.**

| Close code | Meaning | Client action |
|------------|---------|---------------|
| 1000, 1001 | normal close, going away | reconnect only if still needed, after 1 s |
| 1006, network error, no `pong` | connection lost | exponential backoff with full jitter: delay = random(0, min(60 s, 1 s * 2^attempt)); reset `attempt` after 60 s of stable connection |
| 4000 `max_age` | hourly renewal | immediate reconnect with a new ticket |
| 4001 `key_rotated` | profile key version changed | run sync for the profile (log and keys), then reconnect |
| 4003 `forbidden` | device revoked, removed or grant revoked | stop Teamwerk for the profile; run a full sync |
| 4008 `rate_limited` | frame rate exceeded repeatedly | backoff of at least 30 s; client bug, logged locally |
| 4009 `bad_frame` | malformed frame | backoff of at least 30 s |
| 4029 `room_full` | room cap reached | retry after 60 s, then backoff; show "Teamwerk is vol (25 verbindingen)" |
| HTTP 401, 403 on ticket or upgrade | auth failure | stop; run a full sync |
| HTTP 429 | ticket rate limit | wait `Retry-After` |

Reconnect attempts stop when no visible tab needs the socket. If the service worker restarts, content scripts notice the closed port (`onDisconnect`), reconnect it after a random delay of 0 to 2 seconds and re-send visibility and route; the worker then reconnects the socket.

### 18.5 Ticket and WebSocket authentication

Ticket issuance (`POST /v1/profiles/{id}/presence/ticket`, device auth with request signature, 11.2) checks in D1: device active in the profile, grant active, profile not deleted, Teamwerk enabled on the instance. It returns a ticket:

```
claims = { "v": 1, "p": profile_id, "d": device_id, "u": user_id, "kv": current_kv,
           "exp": now_s + 60, "n": b64u(16 random bytes) }
ticket = b64u(utf8(jcs(claims))) + "." + b64u(HMAC(PRESENCE_TICKET_KEY, enc("ebs/v1/ticket", jcs(claims))))
```

`PRESENCE_TICKET_KEY` is a 32-byte Worker secret. The ticket contains only characters allowed in a WebSocket subprotocol token (base64url and `.`).

On `GET /v1/presence/ws` with `Upgrade: websocket`, the Worker:

1. requires `Origin` to be `chrome-extension://<id>` for an id in `ALLOWED_EXTENSION_IDS` (web pages cannot connect even with a stolen ticket);
2. reads the ticket from `Sec-WebSocket-Protocol`, verifies the HMAC and `exp`;
3. forwards the request to the Durable Object `idFromName(claims.p)`.

The Durable Object rejects a ticket nonce it has seen before. It records used nonces with their `exp` in its own SQLite storage, because memory is lost when the object hibernates or is evicted, and an alarm deletes them 2 minutes after expiry. This is the only thing the object stores. It also rejects `kv` lower than the room's highest seen `kv`, enforces the room cap, and accepts the socket with `ctx.acceptWebSocket(ws, [device_id, user_id])`, storing `{device_id, user_id, conn_id, kv, connected_at}` with `serializeAttachment`. If a socket for the same `device_id` already exists, the older one is closed with 1000 (one socket per device per room).

Why a ticket instead of the device token on the socket: browsers cannot set an `Authorization` header on a WebSocket, the device token must never be in a URL or a subprotocol header that intermediaries may log, and the request signature scheme (11.2) covers HTTP requests. A 60-second single-use ticket, obtained through a signed request, bridges the two.

### 18.6 Keys

```
K_pres(kv)  = HKDF(DK_kv, Z32, enc("ebs/v1/presence", p, u32(kv)))      deriveBits(256), then imported as an HKDF base key
K_sess      = HKDF(K_pres(kv), salt = sess, info = enc("ebs/v1/pres-sess", p, u32(kv), device_id))   AES-GCM-256
K_focus     = HKDF(NK, Z32, enc("ebs/v1/focus", p))                      HMAC-SHA-256
```

- WebCrypto cannot `deriveKey` into an HKDF key (the target algorithm needs a length that HKDF keys do not have). `K_pres(kv)` is therefore computed with `deriveBits` (256 bits) and immediately imported with `importKey("raw", bits, "HKDF", false, ["deriveKey"])`; the bits buffer is zeroed afterwards. The same pattern applies to any HKDF-from-HKDF step.
- `sess` is 16 random bytes, generated per socket connection by the sender. Each connection therefore encrypts under its own key, which makes a counter nonce safe: `nonce = u32(0) || u64(seq)`, with `seq` starting at 1 for each `sess` and incremented per frame. No nonce ever repeats under one key, regardless of how many frames all members send over the lifetime of `DK_kv` (random nonces would approach the 2^32 bound at 15 frames per second across many members and months).
- Receivers derive the sender's `K_sess` from the `sess` in the frame header and cache it per `(device_id, sess)`.
- `K_focus` derives row references (18.9). It uses `NK` because row references must match across key versions during a rotation; they are only ever sent inside encrypted frames.

### 18.7 Frame format

**Member frames** are binary WebSocket messages, relayed unchanged to the other sockets in the room:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `ver` = 0x01 |
| 1 | 1 | `kind` = 0x10 (member frame) |
| 2 | 4 | `kv`, u32 |
| 6 | 24 | sender `device_id`, ASCII (`d_` plus 22 characters) |
| 30 | 16 | `sess` |
| 46 | 8 | `seq`, u64 |
| 54 | 8 | `ts`, u64, sender clock in Unix ms |
| 62 | n | `ct`, AES-GCM ciphertext including the 16-byte tag |
| 62 + n | 64 | `sig`, ECDSA P-256 (P1363) |

```
header = bytes[0 .. 62)
aad    = enc("ebs/v1/pres-aad", p, header)
ct     = AES-GCM-Encrypt(K_sess, nonce = u32(0) || u64(seq), pt, aad)
sig    = ECDSA-Sign(sign_priv, enc("ebs/v1/pres-sig", p, header, ct))
```

`pt` is the payload JSON (18.8) prefixed with `u32(len)` and zero padded to exactly 256 bytes, or to 512 or 1,024 bytes if it does not fit (only `hello` and route frames with a long follow path and several focus refs; the largest valid `hello` is about 720 bytes of JSON). Payload JSON is at most 1,020 bytes. Fixed sizes make status, cursor, focus and most route frames indistinguishable by length. A member frame is therefore 62 + 272 + 64 = 398 bytes (or 654 or 1,166). The server rejects binary frames over 1,280 bytes.

The signature is per frame. It is what makes a cursor or marker attributable to a specific device in the signed membership log; a shared presence key alone would let any member forge frames in another member's name. ECDSA P-256 signing and verifying cost well under a millisecond in WebCrypto, which is affordable at the capped rates of 18.11.

**Control frames** are text WebSocket messages sent by the Durable Object (plaintext JSON, server-asserted, never trusted for identity):

```ts
{ t: "welcome", conn_id: string, kv: number, max_age_s: 3600,
  present: Array<{ device_id: Id<"d">, user_id: Id<"u">, since: number }>,
  limits: { max_frame: 1280, rate: 20, burst: 30 } }
{ t: "join",  device_id: Id<"d">, user_id: Id<"u"> }
{ t: "leave", device_id: Id<"d"> }
{ t: "error", code: "rate_limited" | "frame_too_large" | "bad_frame" | "sender_mismatch" }
```

The only text frame a client sends is `ping`; the auto-response is `pong`. Any other client text frame closes the socket with 4009.

### 18.8 Payloads

```ts
type Payload =
  | { k: "hello", s: Status, r: Route | null, f: Focus | null, h: Head }   // after welcome, and once after each "join" (random 0 to 500 ms delay)
  | { k: "st", s: Status, h: Head }                                        // on change and every 30 s
  | { k: "rt", r: Route | null }                                   // on navigation
  | { k: "cu", c: Cursor | null }                                  // pointer movement; null when the pointer leaves the page or the tab is hidden
  | { k: "fo", f: Focus | null }                                   // when a row or record is opened or closed
  | { k: "bye" }                                                   // before a normal close
type Status = "active" | "idle" | "paused"                         // idle after 60 s without input
type Head   = [number, string]   // the sender's verified log head: [seq, b64u(full 32-byte hash)]
type Route  = { id: string,          // normalised page id, for example "bank.import"; max 48 chars, [a-z0-9.]
                follow?: string }    // path and query on the e-Boekhouden origin, max 400 chars (18.10)
type Cursor = { a: Anchor, x: number, y: number,      // x, y: integers 0..10000, relative to the anchor's box
                v?: { a: Anchor, y: number } }        // scroll context: top visible anchor and offset
type Focus  = { refs: RowRef[], m: "open" | "edit" }  // at most 5 refs
type Anchor = string   // grammar in 18.9
type RowRef = string   // "r_" + 22 base64url characters
```

Never sent, by construction: field values, amounts, typed text, text content of the page, selected text, DOM snippets, raw selectors that contain text, raw URLs outside the follow rule, screenshots, and anything about other tabs or administrations. The service worker enforces this with a strict validator: only the keys above, exact types, the anchor grammar, lengths and value ranges. It applies the validator to every outgoing payload (input from content scripts) and every incoming payload (frames from other members); anything else is dropped. Content scripts never construct payload JSON themselves (15.7).

### 18.9 Anchors, cursors and row references

Row keys are the logical identifiers of rows and records the extension already uses, for example `bankline/8812345` or `relatie/1234`. The content script sends row keys to the service worker, which turns them into row references:

```
RowRef(rowkey) = "r_" + b64u(HMAC(K_focus, utf8(rowkey)))[0 .. 22]     (128 bits)
```

The content script asks the worker for the refs of the rows it renders (`tw:rows`), so it can match incoming refs to local rows without holding `K_focus`.

Anchor grammar (regular expression applied by the validator):

```
^(row:r_[A-Za-z0-9_-]{22}
 |cell:r_[A-Za-z0-9_-]{22}:[a-z0-9_.-]{1,32}
 |el:[a-z0-9_.-]{1,48}
 |nav|main|page)$
```

- `row:<ref>`: a table row with a row key. `cell:<ref>:<column>`: a cell, where `column` is a column id from the extension's per-page column map.
- `el:<id>`: an element from a per-page allow-list of stable landmarks (for example `el:import.dropzone`), mapped by the extension from element ids or attributes, never from text.
- `nav`, `main`, `page`: fallbacks (navbar, main content box, document).
- The content script picks the innermost element under the pointer that has an anchor, and computes `x` and `y` as the pointer's position within that element's bounding box in units of 1/10000. This is independent of viewport size, zoom and scroll position.
- `v` describes where the sender is scrolled (the topmost visible anchor and the offset into it), so receivers can show "Dion is lager op de pagina" with an edge indicator when the cursor is off screen.

Receivers resolve the anchor in their own DOM. If it is not present (different filter, sorting or pagination), the cursor is hidden rather than drawn in the wrong place.

### 18.10 Rendering and interaction rules

1. **Names and identity come from the verified membership log only.** A frame is attributed to the device in its header only after its signature verifies against that device's `sign_pub` in the verified log and that device is active. The label shows the user's log name (`owner_name`, `user_name`, `set_name`, 9.3). Server control frames (`present`, `join`, `leave`) are hints: a device listed by the server that is not active in the log is never shown with a name; it is ignored, and if it persists the client records a local security notice.
2. **Avatars in the navbar.** Up to 5 avatars plus "+n", each with initials and a color derived from `H(user_id)`. Hover or tap shows "Dion · Importeren" (the route id mapped to a Dutch label by the extension; unknown routes show "Elders in e-Boekhouden"), the status ("actief", "inactief", "gepauzeerd"), and "Volg".
3. **Volg.** Available when the colleague's route has a `follow` path. Clicking it makes the service worker navigate the user's own visible tab for this profile with `chrome.tabs.update` to `<the follower's own e-Boekhouden origin> + follow`, after validating that `follow` starts with `/`, contains no `//`, no scheme and no backslash, matches the URL pattern registered for the route id, and contains only the query parameters allow-listed for that route id. The sender builds `follow` with the same rules. Navigation happens only on the user's click, never automatically. Content scripts never receive other members' follow paths.
4. **Cursors.** Drawn only when the colleague's route id equals the tab's route id. The overlay interpolates between updates and removes a cursor 10 seconds after its last update or immediately on `cu: null`.
5. **"Bezig" markers.** A colleague's focus refs that match local rows get a small "bezig: Dion" marker. When the user's own focus refs intersect a colleague's (`open` or `edit`), the extension shows a dismissible banner: "Dion heeft deze regel ook open." It never prevents editing or saving; last-write-wins still applies to synced data.
6. **Overlay.** One host element per tab, attached by the content script, with a closed shadow root, `position: fixed`, `pointer-events: none` (except the navbar avatar menu), and the maximum z-index. All names and labels are inserted with `textContent`. Styles are inside the shadow root.
7. **Muting.** "Verberg cursor van <naam>" per colleague, stored locally; it hides that member's cursor and markers on this device.

### 18.11 Rate limits and caps

| Limit | Value | Enforced by |
|-------|-------|-------------|
| Cursor frames while moving | at most 15 per second (minimum interval 66 ms, coalesced to the latest position) | client |
| Cursor frames when idle | 0 (nothing is sent while the pointer does not move; one `cu: null` when it leaves) | client |
| Status frames | on change and every 30 s | client |
| Focus and route frames | on change, focus debounced 250 ms | client |
| Frames per connection | token bucket of 20 per second, burst 30; excess frames are dropped with an `error` frame; 10 s of continuous excess closes with 4008 | Durable Object |
| Frame size | 1,280 bytes binary; text only `ping` | Durable Object |
| Room size | 25 sockets per profile (`ROOM_CAP`) | Durable Object |
| Sockets per device | 1 per room, 3 in total | Durable Object (per room), client (total) |
| Tickets | 10 per minute per device | Worker |
| Incoming verification | the client drops frames from a sender beyond 20 per second before verifying them, to bound CPU use | client |

### 18.12 Privacy controls

1. **Setting.** "Teamwerk" is a plain extension setting in the options page, off by default, stored on the device like the other extension settings. Next to the switch, the options page states what is shared (page, cursor position relative to page elements, which rows are open, status) and what is never shared (18.8).
2. **Pause.** A "Pauzeer Teamwerk" toggle in the popup and the navbar menu. While paused, the client sends only `st` frames with `s: "paused"` and no route, cursor or focus; it keeps receiving. Others see "gepauzeerd".
3. **Reciprocity and visibility.** Only users who switched the setting on connect, and every connected client sends `hello` and periodic `st` frames, also when paused, so nobody can watch silently with an unmodified client. The navbar menu lists everyone in the room, including idle and paused members, with names from the log. Connected devices that the server lists but that send no verified frames are shown as "verbonden" with the log name of their user, so a modified, silent client is still visible.
4. **No server storage.** Presence exists only in transit and in the Durable Object's memory for socket bookkeeping. Nothing about presence is written to D1, Durable Object storage (which holds only used ticket nonces), the audit log or logs (13.1). Clients keep presence state in memory only.

### 18.13 Server behaviour (Durable Object `PresenceRoom`)

1. One object per profile, addressed by `idFromName(profile_id)`. EU self-hosters SHOULD create the namespace with the EU jurisdiction option.
2. Uses the WebSocket Hibernation API (`acceptWebSocket`, `webSocketMessage`, `webSocketClose`, `setWebSocketAutoResponse`). Its storage holds only used ticket nonces until shortly after they expire (18.5). Attachments hold only `{device_id, user_id, conn_id, kv, connected_at}` for the lifetime of the socket.
3. On a binary message: check size, `ver`, `kind`, that the header's `device_id` equals the socket's `device_id` (else `error sender_mismatch` and drop), and the token bucket; then send the bytes unchanged to every other socket in the room. No buffering, no delivery to sockets that join later, no echo to the sender.
4. On accept and close: send `join` and `leave` control frames to the other sockets.
5. Internal kick interface, callable only by the Worker through the Durable Object stub (not exposed on any public route): `kick({device_ids?, user_ids?, all?, code})`. The Worker calls it when it revokes a device (code 4003), accepts a log append with removals (4003 for removed devices) or a `rotate_key` (4001 for all), revokes a grant (4003), deletes a profile (4003, all) or deletes an account (4003).
6. Token bucket state is kept in memory only; after hibernation it starts full, which is acceptable because hibernation only happens when the room is quiet.

### 18.14 Key rotation and membership changes

- After a rotation the Worker kicks every socket with 4001. Clients sync the log and keys and reconnect with tickets carrying the new `kv`. The room then rejects tickets with a lower `kv`, and receivers drop frames whose `kv` differs from their own current `kv`.
- A removed device or user is kicked with 4003 and cannot obtain new tickets. Because it never receives `DK_(kv+1)`, it cannot read presence after the rotation even if a malicious server let it stay connected.
- A new member appears in the room only after approval, because tickets require an active device.

### 18.15 Replay protection

A receiver accepts a member frame only if all of these hold:

1. `ver`, `kind` and lengths are valid; `kv` equals the receiver's current `kv` for the profile. Exception for staleness detection: a frame with a lower `kv` that the receiver can still reach through the history chain is verified and decrypted only to read `h`; it is never rendered, and the receiver shows "<naam> gebruikt een verouderde ledenlijst" (rule 7).
2. The sender device is active in the verified log, and `sig` verifies with its `sign_pub`.
3. `|ts - now| <= 120 s` (receiver clock).
4. For the pair `(device_id, sess)`: `seq` is greater than the highest `seq` accepted so far. State per pair is kept in memory while frames arrive and for 5 minutes after the last one.
5. If `sess` differs from the sender's current `sess`, the frame starts a new session only if its `ts` is greater than the last `ts` accepted from the current `sess`; otherwise it is dropped. This stops the server from interleaving a recorded older session.
6. Decryption succeeds and the payload passes the validator.
7. Head comparison for `hello` and `st`: if the sender's head seq is greater than the receiver's verified head, the receiver fetches and verifies the log; if that fails, it stops pushing to the profile and shows the fork warning (9.7). If the sender's head is lower and the receiver's log contains a `rotate_key` after the sender's head, the receiver shows "<naam> gebruikt een verouderde ledenlijst; vraag <naam> om op Nu synchroniseren te klikken" (the stale writer case, 14.3 T7). If the seqs are equal, the hashes MUST be equal, else the fork warning is shown. The stale sender learns the same from the receivers' frames (10.13 step 3.5).

Profile id and header are bound by the associated data and the signature, so frames cannot be replayed into another room, another key version or under another sender.

### 18.16 Costs for self-hosters

Durable Objects bill per request and per unit of active duration; incoming WebSocket messages are billed at a fraction of a request, and hibernated objects incur no duration charges. Cursor traffic dominates. With the caps above, one room is bounded at 25 sockets times 20 frames per second inbound. Self-hosters should check which Cloudflare plan offers Durable Objects with WebSocket hibernation, and can switch Teamwerk off for the whole instance with `TEAMWERK_ENABLED = false` (the ticket endpoint then answers `403 forbidden` and the extension hides Teamwerk).


## 19. Summary of design choices

- Unit of data and membership: the profile, bound to one administration and one owner, shareable, with its own DK (rotated) and NK (stable). Several profiles per administration are allowed; the extension switches per administration and remembers the choice per device.
- Administration to profile mapping: the administration number lives only in encrypted profile meta; each client decrypts the metas of its profiles and builds a local index. A server-pepper HMAC was rejected (trivially reversible by the operator over a small number space), a per-user HMAC was rejected (extra key distribution, no help for shared profiles).
- Crypto: P-256 ECDH and ECDSA, HKDF-SHA-256, AES-256-GCM, HMAC-SHA-256, PBKDF2-SHA-256 600,000 iterations for the recovery kit, all WebCrypto in Chrome 116. Device private keys are non-extractable and live in the extension origin's IndexedDB, never in `chrome.storage.local` or content scripts.
- Records: random 96-bit nonce, AAD binds profile, record id, key version, record version and delete flag; padded to size buckets; HMAC record ids; last-write-wins with a hybrid clock (clamped against far-future clocks) and per-record compare-and-set versions. Tombstones are kept for the life of the profile, so cursors never expire and a client never deletes cached data on the server's word alone. Rollbacks of records, log, key version or meta raise a security warning and stop pushes.
- Membership: signed, hash-chained log per profile, sent as exact canonical bytes and chained by a hash over the body only (ECDSA signatures are malleable). Simple validation rules, key commitments, encrypted display names, a cap of 150 active devices, rotations only after a removal, by the owner, or for the nonce budget. The server checks that wraps, history and meta match the entries exactly. Head gossip in records and in Teamwerk frames detects forks and members kept stale by a server that withholds a rotation; that last case is detected, not prevented.
- Access: admins and owners grant server-side; grants stay pending until a member device approves with one click, showing a 100-bit device code that resists offline grinding, so approvals work asynchronously. Comparison is recorded as `verified`. Auto-approve exists per profile and is labelled as trusting the server.
- Connection: OAuth 2.0 authorization code with PKCE through `chrome.identity.launchWebAuthFlow`, exact `chromiumapp.org` redirect validation against an extension id allow-list, 60-second single-use codes bound to the device keys; the consent form protected by `Origin`, `Sec-Fetch-Site` and a session-bound `csrf` field; the pairing code as automatic fallback when the auth window fails or is closed, and as a secondary option; opaque hashed device tokens rotated every 30 days and always combined with ECDSA request signatures that include a nonce (stored for the non-idempotent endpoints) over a normalised URL.
- Revocation: immediate server-side cut-off, then removal plus rotation by any eligible remaining member; lazy, leased, idempotent re-encryption in `(kv, id)` order with an `after` cursor, batches of 200, server rate limits and an explicit completion call. Re-grants re-add removed devices with their original keys.
- Recovery: a per-user recovery pseudo-device whose private keys (with their public keys) are encrypted under a printed 128-bit key with PBKDF2 pinned at 600,000 iterations; it is attested by the creating device, added automatically to every profile of the user, and included in every rotation, so the kit never needs reprinting.
- Dashboard: same-origin static app with passkeys first and email codes as fallback, strict CSP, no keys; sensitive actions need fresh user verification.
- Logging: fixed-field operational logs with route templates; audit events without contents or secrets; IP prefixes only.
- Teamwerk: one Durable Object room per profile with WebSocket hibernation, opened from the service worker only while an e-Boekhouden tab is visible, authenticated with a 60-second single-use ticket obtained through a signed request. Frames are encrypted under per-connection keys from a presence key derived from DK, signed per frame, protected against replay with per-session sequence numbers, padded to fixed sizes, relayed without storage, and attributed only through the signed membership log, which now carries display names. Route ids, anchor-relative cursors and HMAC row references are sent; field values, amounts and typed text never are. `hello` and `st` frames carry the sender's log head. Teamwerk is a plain extension setting, off by default; pause and visible room membership are mandatory.
- GDPR: server export of all held data as NDJSON (ciphertext included), decrypted JSON export from the extension, defined retention and deletion semantics including D1 Time Travel.

Open questions that most need an owner decision before implementation: Q1 (personal versus shared preferences), Q4 and Q5 (who may approve and who may invite), Q2 (NK rotation) and Q6 (app lock for stolen laptops).

---

## Appendix A. Test vectors

Computed with WebCrypto (HKDF, AES-GCM, PBKDF2) and Node's `crypto` (P-256 point arithmetic for fixed private keys, HMAC, SHA-256). Fixed keys are for testing only. Note that every `enc` item, including fixed-width integers, gets its own 4-byte length prefix.

Inputs:

```
p      = "p_AAAAAAAAAAAAAAAAAAAAAA"
DK_1   = 32 bytes of 0x01
NK     = 32 bytes of 0x02
nonce  = 00 01 02 03 04 05 06 07 08 09 0a 0b
```

A.1 `enc`:

```
enc("ebs/v1/rec", p, u32(1)) =
0000000a6562732f76312f72656300000018705f414141414141414141414141414141414141414141410000000400000001
```

A.2 Profile keys and ids:

```
K_rec(1)     = fc01b9493746d84c36c28fe66a2a4fa35f40c7f1f7054ccf7589c754c543500d
dk_commit(1) = UhPsreJqDnLZNw09_nb4OnYE6uKg1R71gADqgRGWgnw
K_rid        = 908edaf04024cb5f3aefbd1cd9e92225205c1038e58b5305144eef07d92d1a55
rid("hiddenLines/8812345") = xXzeTbdADaKcinVB6pfXAC8JCKV59_PldBRVJhDlSkU
nk_commit    = 1rTMOJp4kLEWwAiHfZhcMKPvziHyfuQKAPYKQfmF7Rw
```

A.3 Record encryption (version 1, not deleted, kv 1, the nonce above):

```
payload JSON (129 bytes, bucket 256):
{"k":"hiddenLines/8812345","v":{"hidden":true},"t":1793270400123,"d":"d_AAAAAAAAAAAAAAAAAAAAAA","h":[1,"AAAAAAAAAAAAAAAAAAAAAA"]}
SHA-256(aad) = 2d22f7122da6aa4b9cb4636dbedcb8686f1895b18b221b5db3e918e39d91e07e
len(ct)      = 272
SHA-256(ct)  = 3d30338451676cc614bfefb46d9debe3f4a9bfbff3af87752070b13bfeb746f2
GCM tag      = G2Uq7l1e_RGaF_AjgO7wMw
```

A.4 Device code (sign private scalar = 32 bytes of 0x11, ECDH private scalar = 32 bytes of 0x22):

```
sign_pub    = BAIX5hfwtkQ5KCePlpmeaaI6TywVK99tbN9m5bgCgtTtGUp968uXcS0t2jyoWqh2Wlb0X8dYWZZS8ol8ZTBuV5Q
ecdh_pub    = BNZak5d8qj0bCBhS_1ennkZfFmBXcwS66tUF3TpIWJzzUBheiVNy32Ih6joTdVfkc_3bZ1XwW9UHw8Uz_OnJEoU
device_jkt  = sN-EQw4uFJKoATslDfCvN31HRW1xga-Gb-TaHIs5g5g
device code = P3FR 8GRE 5RA9 5A01 7CJG
```

A.5 Wrap (ephemeral private scalar = 32 bytes of 0x33, recipient = the ECDH key of A.4, `to = "d_BBBBBBBBBBBBBBBBBBBBBB"`, `from = "d_AAAAAAAAAAAAAAAAAAAAAA"`, `kv = 1`, `at = 1`, the nonce above, plaintext `NK || DK_1`):

```
epk     = BFGnWAgziY6hsYPL1zUKQJkHjG7xweGOlwzXaDA18l59ARBSJxKwtafP8IFoVIaYSpTmgx7axG5zYPqdg0p6gaE
Z       = 5f1c591a4bba11bee0d5a2a642eef6385d59aab8d6a6f151d8d857e2e822a67f
KEK     = b3c78a74f8580b443eec69f820c1960b28cbac610c35aeb7b13dc9db57fca9ea
ct      = Q7dckHXQZ7aT1ku0lPoB4RbgVhPQ47Q3fJ1A5vAaDQzzU5lQxu4gWA0_0_41xLiRHMlClPjqLmBBZ6aT6qbKfSBe62MVe7gRiSitzPNoTeU
```

(The signature is randomized and has no fixed vector; verify it round-trips.)

A.6 Recovery key (`rk` = bytes 00 01 ... 0f, `salt` = 16 bytes of 0xaa, 600,000 iterations, `user_id = "u_AAAAAAAAAAAAAAAAAAAAAA"`, `recovery_device_id = "d_CCCCCCCCCCCCCCCCCCCCCC"`):

```
recovery key = 000G-40R4-0M30-E209-185G-R38E-1XXM-WSWQ
S            = 0a43a998a1565901ab31ca4142c8d7f645cbb1097c52653dcc73c7b9a1db6b89
K_rk_kek     = fd6577b2c89ef82225e00ff74a86f4b28ada8b834b337d94ca5f32a7a6ea82ac
```

A.7 JCS serialization and log hash (serialization test only; this body is not a valid first log entry). On the wire, `body_jcs` is exactly the `jcs` string below:

```
input  = {v:1, profile_id:p, seq:1, prev:b64u(Z32), type:"set_policy", ts:1793270400123,
          author:"d_AAAAAAAAAAAAAAAAAAAAAA", payload:{approvers:"owner", auto_approve:false}}
jcs    = {"author":"d_AAAAAAAAAAAAAAAAAAAAAA","payload":{"approvers":"owner","auto_approve":false},"prev":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","profile_id":"p_AAAAAAAAAAAAAAAAAAAAAA","seq":1,"ts":1793270400123,"type":"set_policy","v":1}
SHA-256(enc("ebs/v1/log-sig", jcs)) = 7c1ae728cfbab9d1059e1bb62c2fa35f8cf12763b4b3e65c6cdef36f065eebc5
hash = b64u(H(enc("ebs/v1/log-hash", jcs)))  = Py2-lyNHdKfdiqnbuGkrtOWH_IpE1y8wifH89uvKet0   (body only, 9.1)
```

A.8 PKCE (verifier = b64u of bytes 00 01 ... 1f):

```
code_verifier  = AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8
code_challenge = 6oZqdX5MOLq_qBJ8vppAnT4fk6AP8UiP9zX8-Rev_9A
```

A.9 Teamwerk keys (same `p`, `DK_1`, `NK`; `sess` = 16 bytes of 0x44; `device_id = "d_AAAAAAAAAAAAAAAAAAAAAA"`). `K_pres(1)` is computed with `deriveBits` and re-imported as an HKDF key (18.6); `K_sess` is the `deriveBits` output of HKDF from that key, which equals the AES key `deriveKey` produces:

```
K_pres(1)                 = 530a8abca3230bd4994f98891051c7b5f4bb80723bfc78f311feca75efb90c8d
K_sess                    = 8228dd84473586ec4025f1de2ee757d84f82ee5915a1e0054b5766ce58d4a3d7
K_focus                   = 9bd323630f89855b7ec1e71f26d235c6cbf94f2713d17a361f13d1c93d6143da
RowRef("bankline/8812345") = r_-b7zA2POPteaDsQQIYqPZ-
nonce for seq 1           = 000000000000000000000001
```

A.10 Encrypted display name (9.3; same `p` and `NK`; `user_id = "u_AAAAAAAAAAAAAAAAAAAAAA"`; name `"Dion de Vries"` (13 bytes, padded to 128); nonce = 00 01 ... 0b):

```
K_name = d11b40bdd349a52b78dd59997aa9fce39f8b4226d70b4d4f086571e8b0e4843c
EncName.nonce = AAECAwQFBgcICQoL
EncName.ct    = xEA-SOrHyIZSI3ITKf7S38vHQw_B_NoExbxldOXaaEW36hUJunWq3A-rBJD7Gp_m4uaVzLp-WQM5F2shVb4rafDJ3sEaSlNBuU_1QTL1IiopnpAe14jKVCnnuPcL5eKOtrcJrHtU6wkpiaEUQJdj67xgO-v5Y0DzAm5RniHAVikrHVW_8QEUUIGbz306TpJV
len(ct)       = 144
```
