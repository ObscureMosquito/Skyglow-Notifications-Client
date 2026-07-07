# Skyglow Notifications Protocol Specification

**Version:** 2 (`SGP_VERSION = 0x02`)  
**Last Updated:** May 2026

---

## 1. Overview

Skyglow Notifications (SGN) is a decentralized push notification system designed as an alternative to Apple Push Notification Service (APNS). It enables third-party notification delivery to iOS devices via a persistent TLS connection between a client daemon and a server.

The system consists of three layers:

1. **Service Discovery** — DNS TXT record resolution to locate the server
2. **Binary TCP Protocol** — A persistent TLS connection carrying length-prefixed binary frames for authentication, notification delivery, and device token management
3. **HTTP API** — Used during initial device discovery by notification senders to submit push messages (out of scope for this document)

---

## 2. Service Discovery

### 2.1. Server Address

Each SGN server has a **server address** — a domain string of **at most 16 characters** (e.g., `skyglow.es`). This address is stored on the client during registration and is embedded into device tokens.

### 2.2. DNS TXT Record Resolution

The client resolves the server's IP address and port at startup via DNS TXT records. The DNS lookup prepends `_sgn.` to the server address:

```
_sgn.<server_address>     e.g. _sgn.skyglow.es
```

### 2.3. TXT Record Format

The TXT record contains space-separated `key=value` pairs:

```
"tcp_addr=143.47.32.233 tcp_port=7373 http_addr=https://sgn.example.com"
```

| Key         | Description                                                  | Required    |
| ----------- | ------------------------------------------------------------ | ----------- |
| `tcp_addr`  | IPv4 address of the TCP protocol server                      | Yes         |
| `tcp_port`  | Port number of the TCP protocol server (TLS)                 | Yes         |
| `http_addr` | Base URL of the HTTP API (push submission + cert auto-fetch) | Recommended |

If `http_addr` is set, the client's prefs UI can fetch the server's public
certificate automatically — see §3.4. Without it, users must import the PEM
file manually.

**Important:** `tcp_port` must point to the TLS-enabled TCP protocol listener, **not** the HTTP API port. These are distinct services running on different ports.

### 2.4. DNS Caching

Clients cache resolved DNS records locally (SQLite) and use cached values on subsequent startups. The cache TTL is **1 hour** (3600 seconds). The cache is refreshed asynchronously in the background after a successful connection.

---

## 3. Transport Layer

### 3.1. TLS Connection

All TCP protocol communication occurs over a TLS connection. The server uses a self-signed X.509 certificate. The client obtains the server's public certificate **out of band before the first connection** (see §3.4) and uses **certificate pinning** — only the pinned certificate is trusted.

- **Protocol:** TLS 1.2+ (SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are explicitly disabled)
- **Certificate validation:** Pinned server certificate only; the system CA store is **not** consulted
- **Pinning mechanism:** The pinned PEM is added to an empty `X509_STORE` via `X509_STORE_add_cert`; the server's presented chain must terminate at that exact certificate
- **Connection model:** Single persistent long-lived connection; client reconnects with exponential backoff on failure
- **TCP_NODELAY:** Enabled on the socket
- **Socket timeouts:** 10 seconds for both send and receive
- **SIGPIPE:** Must be ignored (`SIG_IGN`) to prevent process termination

### 3.2. Frame Format

All messages in both directions use identical binary framing:

```
┌────────┬─────────┬──────┬──────────┬──────────────────┬──────────────────────────────┐
│ Byte 0 │ Byte 1  │ Byte 2│ Byte 3  │ Bytes 4-7        │ Bytes 8+                     │
│ Magic  │ Version │ Type │ Reserved │ Payload Length   │ Payload                      │
│ 0x53   │ 0x02    │ u8   │ 0x00     │ big-endian u32   │ N bytes                      │
└────────┴─────────┴──────┴──────────┴──────────────────┴──────────────────────────────┘
```

| Field          | Size    | Description                                             |
| -------------- | ------- | ------------------------------------------------------- |
| Magic          | 1 byte  | Always `0x53` (ASCII `S`)                               |
| Version        | 1 byte  | Protocol version, currently `0x02`                      |
| Type           | 1 byte  | Message type identifier (see Section 4)                 |
| Reserved       | 1 byte  | Must be `0x00`. Non-zero values cause a protocol error. |
| Payload Length | 4 bytes | Unsigned 32-bit integer, **big-endian** (network order) |
| Payload        | N bytes | Type-specific binary data. Max `4096` bytes.            |

**Header size:** 8 bytes fixed.  
**Maximum payload:** 4096 bytes (`SGP_MAX_PAYLOAD_LEN`).

### 3.3. Byte Order

All multi-byte integers in payloads are encoded in **big-endian** (network byte order). This applies to:

- The 4-byte payload length in the header
- All `int64_t` timestamps and sequence numbers (8 bytes)
- All `uint32_t` version numbers and data lengths (4 bytes)
- All `uint16_t` string lengths (2 bytes)

### 3.4. Certificate Provisioning

Because the daemon's TLS layer pins a single self-signed certificate (§3.1),
the client must obtain that certificate **before** the first TCP connection
can succeed. Provisioning is performed by the prefs UI, never by the daemon
itself, and is decoupled from device registration (§5). Two paths are
supported:

**Auto-fetch (recommended).** The prefs UI:

1. Resolves `_sgn.<server_address>` TXT and reads the `http_addr` value.
2. Issues `GET <http_addr>/snd/server_cert.pem` over HTTPS. TLS chain
   validation is intentionally bypassed for this single request — the user
   sees the parsed Subject/Issuer in a confirmation dialog before the PEM is
   saved, which serves as the trust gate.
3. On confirmation, writes the PEM to disk and records its path in the
   profile plist. Every subsequent daemon connection uses strict pinning
   against that file.

Server-side requirement: a `GET /snd/server_cert.pem` route returning
`text/plain` or `application/x-pem-file` whose body is the exact same PEM
the TLS listener presents. Status code MUST be `200`; the body MUST contain
a valid `-----BEGIN CERTIFICATE-----` block. No authentication, no
revalidation, no `Content-Length` upper bound enforcement beyond the daemon's
ordinary I/O limits.

**Manual import.** The user picks a PEM file via a file picker. The bundle
copies it to the same canonical location and updates the profile plist.
Identical end state to the auto-fetch path; useful when the server lacks an
HTTP component, or when the operator distributes certs out-of-band.

In both paths the cert is bound to a specific profile slot, so different
profiles may pin different servers.

---

## 4. Message Types

### 4.1. Server → Client Messages (`0x1_`)

| Type   | Name            | Description                              |
| ------ | --------------- | ---------------------------------------- |
| `0x10` | S_HELLO         | Server greeting after TLS handshake      |
| `0x11` | S_CHALLENGE     | Authentication challenge nonce           |
| `0x12` | S_AUTH_OK       | Authentication successful                |
| `0x13` | S_NOTIFY        | Incoming push notification               |
| `0x14` | S_DISCONNECT    | Server is closing the connection         |
| `0x16` | S_PONG          | Response to client keep-alive ping       |
| `0x17` | S_POLL_DONE     | All offline messages have been delivered |
| `0x18` | S_REGISTER_OK   | First-time device registration succeeded |
| `0x19` | S_REGISTER_FAIL | First-time device registration failed    |
| `0x1A` | S_PING          | Server-initiated keep-alive ping         |
| `0x1B` | S_TIME_SYNC     | Clock synchronization message            |

### 4.2. Client → Server Messages (`0x2_`)

| Type   | Name            | Description                                                              |
| ------ | --------------- | ------------------------------------------------------------------------ |
| `0x20` | C_LOGIN         | Login handshake initiation                                               |
| `0x21` | C_LOGIN_RESP    | Response to authentication challenge                                     |
| `0x22` | C_POLL          | Request offline (undelivered) notifications                              |
| `0x23` | C_ACK           | Acknowledge receipt of a notification                                    |
| `0x24` | C_DISCONNECT    | Client is closing the connection                                         |
| `0x27` | C_PING          | Client-initiated keep-alive ping                                         |
| `0x28` | C_REGISTER      | First-time device registration request                                   |
| `0x29` | C_REGISTER_RESP | Response to first-time registration challenge                            |
| `0x2A` | C_PONG          | Response to server keep-alive ping                                       |
| `0x2B` | C_FILTER        | Active (routing key, bundle ID) registration set (chunked, full-replace) |

---

## 5. First-Time Device Registration

Before a device can authenticate, it must register with the server to obtain an identity. This is a one-time process.

### 5.1. Sequence

```
Client                                              Server
  │                                                    │
  │──────────── [C_REGISTER 0x28] ────────────────────►│
  │  { public_key_DER, timestamp, version }            │
  │                                                    │
  │◄───────────── [S_CHALLENGE 0x11] ─────────────────│
  │  { 32-byte nonce }                                 │
  │                                                    │
  │──────────── [C_REGISTER_RESP 0x29] ───────────────►│
  │  { timestamp, RSA-PSS signature (nonce ‖ ts) }     │
  │                                                    │
  │◄─────── [S_REGISTER_OK 0x18] or [S_REGISTER_FAIL] │
  │  { server_version, assigned_address }              │
  │                                                    │
```

**The server assigns the device address.** The client
never picks its own identifier, it provides only a freshly generated
RSA keypair and waits for the server to issue an address in
S_REGISTER_OK. This guarantees uniqueness at the namespace level
(server controls the space) and allows the server to encode routing
information into the address itself (e.g. `<hex>@<server-id>`).

### 5.2. C_REGISTER (0x28) Payload

| Offset  | Size       | Field      | Description                                          |
| ------- | ---------- | ---------- | ---------------------------------------------------- |
| 0       | 2          | pubkey_len | Length of DER-encoded public key (BE u16)            |
| 2       | pubkey_len | public_key | RSA-2048 public key in DER format (`i2d_RSA_PUBKEY`) |
| 2+PL    | 8          | timestamp  | Current Unix time, corrected for clock skew (BE i64) |
| 10+PL   | 4          | version    | Protocol version `0x02` (BE u32)                     |

The client generates an **RSA-2048** keypair: the public key is sent to
the server, the private key is stored locally and never transmitted.
The device address field is **absent** — the server assigns it.

### 5.3. S_REGISTER_OK (0x18) Payload

| Offset | Size     | Field          | Description                                       |
| ------ | -------- | -------------- | ------------------------------------------------- |
| 0      | 4        | server_version | Server's protocol version (BE u32)                |
| 4      | 2        | addr_len       | Length of the assigned address (BE u16, max 255)  |
| 6      | addr_len | address        | Server-assigned device address (UTF-8)            |

The address format is server-defined; the client treats it as an opaque
UTF-8 token. The current SGN reference server issues addresses of the
form `<32 hex chars>@<server-id>`, but clients MUST NOT rely on or
parse this format — only round-trip the bytes verbatim for future
authentication.

Max address length is **255 bytes**. Frames exceeding this are
rejected as protocol errors.

**Address charset.** Clients MUST reject any address containing bytes
outside `[A-Za-z0-9._@-]`. This blocks path traversal, embedded NULs,
control characters, and format-string specifiers in a value that will
end up in the profile plist, UI displays, and log lines. A server
issuing addresses outside this charset is treated as malformed.

### 5.4. S_REGISTER_FAIL (0x19) Payload

| Offset | Size       | Field      | Description                             |
| ------ | ---------- | ---------- | --------------------------------------- |
| 0      | 1          | code       | Rejection reason code (u8)              |
| 1      | 2          | reason_len | Length of reason string (BE u16)        |
| 3      | reason_len | reason     | Human-readable rejection reason (UTF-8) |

---

## 6. Authentication Flow

Authentication uses an **RSA-PSS challenge-response** scheme. The client possesses an RSA-2048 private key; the server holds the corresponding public key (exchanged during registration).

### 6.1. Sequence

```
Client                                              Server
  │                                                    │
  │◄───────────── [S_HELLO 0x10] ─────────────────────│
  │  { server_version }                                │
  │                                                    │
  │──────────── [C_LOGIN 0x20] ───────────────────────►│
  │  { address, timestamp, version }                   │
  │                                                    │
  │◄───────────── [S_CHALLENGE 0x11] ─────────────────│
  │  { 32-byte nonce }                                 │
  │                                                    │
  │──────────── [C_LOGIN_RESP 0x21] ──────────────────►│
  │  { timestamp, RSA-PSS signature }                  │
  │                                                    │
  │◄───────────── [S_AUTH_OK 0x12] ───────────────────│
  │                                                    │
  │──────────── [C_FILTER 0x2B] ──────────────────────►│
  │──────────── [C_POLL 0x22] ────────────────────────►│
  │                                                    │
  ▼                                                    ▼
       (persistent bidirectional connection)
```

### 6.2. S_HELLO (0x10) Payload

| Offset | Size | Field          | Description                        |
| ------ | ---- | -------------- | ---------------------------------- |
| 0      | 4    | server_version | Server's protocol version (BE u32) |

Sent by the server immediately after the TLS handshake completes.

### 6.3. C_LOGIN (0x20) Payload

| Offset | Size     | Field     | Description                                          |
| ------ | -------- | --------- | ---------------------------------------------------- |
| 0      | 2        | addr_len  | Length of address string (BE u16)                    |
| 2      | addr_len | address   | The client's registered device address (UTF-8)       |
| 2+AL   | 8        | timestamp | Current Unix time, corrected for clock skew (BE i64) |
| 10+AL  | 4        | version   | Protocol version `0x02` (BE u32)                     |

### 6.4. S_CHALLENGE (0x11) Payload

| Offset | Size | Field | Description                          |
| ------ | ---- | ----- | ------------------------------------ |
| 0      | 32   | nonce | Server-generated cryptographic nonce |

The same S_CHALLENGE message type is used for both login and first-time registration flows.

### 6.5. C_LOGIN_RESP (0x21) / C_REGISTER_RESP (0x29) Payload

Both response types use the same payload format:

| Offset | Size    | Field     | Description                                                 |
| ------ | ------- | --------- | ----------------------------------------------------------- |
| 0      | 8       | timestamp | The timestamp from the original C_LOGIN/C_REGISTER (BE i64) |
| 8      | 2       | sig_len   | Length of RSA-PSS signature (BE u16)                        |
| 10     | sig_len | signature | RSA-PSS-SHA256 signature (see 6.6)                          |

### 6.6. RSA-PSS Signature Scheme

The client produces the signature over a buffer that depends on the flow:

| Flow                          | Signed material                                  |
| ----------------------------- | ------------------------------------------------ |
| Login (`C_LOGIN_RESP 0x21`)   | `nonce ‖ address_utf8 ‖ timestamp_be64`          |
| Registration (`C_REGISTER_RESP 0x29`) | `nonce ‖ timestamp_be64` (no address yet) |

Then:

1. Compute `digest = SHA-256(signed_material)`
2. Apply RSA-PSS padding with `SHA-256` as both the hash and MGF1 hash, salt length = hash length (32)
3. Sign with `RSA_private_encrypt(padded_message, RSA_NO_PADDING)`

For login, the server verifies using the public key stored under the
claimed address. For registration, the server has just received the
public key in the preceding C_REGISTER frame and verifies with that —
the address is not yet bound, so the signed material omits it.

### 6.7. S_AUTH_OK (0x12) Payload

Empty payload (0 bytes). Confirms the client has authenticated.

### 6.8. Clock Skew Correction

The server may send `S_TIME_SYNC (0x1B)` **only after authentication completes**. It contains an 8-byte big-endian Unix timestamp; the client computes `offset = server_time - local_time` and applies this correction to all subsequent timestamps sent in C_LOGIN and C_REGISTER messages. This handles iOS devices with drifted clocks. The server's challenge window is **300 seconds** (`SGP_CHALLENGE_WINDOW_SEC`).

The client rejects offsets exceeding **±172800 seconds (2 days)** as a protocol error. Larger drifts are well outside any plausible real-world clock skew and indicate either a buggy server or an attempt to push timestamps far out of valid replay windows.

### 6.9. Protocol Phase Gating

To defend against unsolicited server-to-client frames that could be used as signing oracles, identity hijacks, or to dispatch pre-auth notifications, the client enforces a strict phase machine and rejects messages outside their allowed phases.

| Phase             | Set by                                  | Allowed server frames                       |
| ----------------- | --------------------------------------- | ------------------------------------------- |
| PreHello          | TLS handshake complete; (re)connect     | `S_HELLO`                                   |
| HelloReceived     | Receiving `S_HELLO`                     | *(client will send C_LOGIN or C_REGISTER)*  |
| ChallengeWait     | Sending `C_LOGIN` or `C_REGISTER`       | `S_CHALLENGE`                               |
| AuthWait          | Receiving `S_CHALLENGE` and sending response | `S_AUTH_OK`, `S_REGISTER_OK`, `S_REGISTER_FAIL` |
| Authenticated     | Receiving `S_AUTH_OK`                   | `S_NOTIFY`, `S_PING`, `S_PONG`, `S_POLL_DONE`, `S_TIME_SYNC` |

`S_DISCONNECT` is accepted in **any** phase. `S_PING` and `S_PONG` are accepted only in `Authenticated`. Any frame outside its allowed phase triggers `SGP_ERR_PROTO` and a clean teardown of the connection (soft error → backoff + reconnect).

Servers MUST NOT rely on sending frames out of phase for any side-effect. Sending `S_REGISTER_OK` to an already-authenticated client to "reissue" an identity, or `S_CHALLENGE` mid-session to refresh credentials, is not supported and will be rejected.

---

## 7. Notification Delivery

### 7.1. S_NOTIFY (0x13) Payload Layout

```
┌──────────────┬──────────┬──────┬────────────┬───────┬──────────────┬──────────┬──────────────┬──────────┐
│ routing_key  │ msg_id   │ seq  │ expires_at │ flags │ content_type │ data_len │ data         │ [iv]     │
│ 32 bytes     │ 16 bytes │ 8 B  │ 8 B        │ 1 B   │ 1 B          │ 4 B (BE) │ data_len B   │ 12 B     │
└──────────────┴──────────┴──────┴────────────┴───────┴──────────────┴──────────┴──────────────┴──────────┘
```

| Offset | Size     | Field        | Description                                           |
| ------ | -------- | ------------ | ----------------------------------------------------- |
| 0      | 32       | routing_key  | SHA-256 hash of the token secret K                    |
| 32     | 16       | msg_id       | Unique notification ID (raw 16 bytes, UUID)           |
| 48     | 8        | seq          | Server-assigned per-device sequence number (BE i64)   |
| 56     | 8        | expires_at   | Expiration timestamp (BE i64), 0 = no expiry          |
| 64     | 1        | flags        | Bit 0: `is_encrypted` (1 = E2EE payload)              |
| 65     | 1        | content_type | Payload format identifier (see 7.4)                   |
| 66     | 4        | data_len     | Length of the data field in bytes (BE u32)            |
| 70     | data_len | data         | Notification payload (plaintext or ciphertext+tag)    |
| 70+DL  | 12       | iv           | AES-GCM IV (**only present when `is_encrypted = 1`**) |

**Minimum payload size:** 70 bytes (empty data, unencrypted).

### 7.2. Notification Processing

1. Look up `routing_key` in the local database to find the associated **bundle ID** and **E2EE key**.
2. If `is_encrypted` is set (flags & 0x01):
   - The `data` field contains `ciphertext || 16-byte GCM auth tag`.
   - Decrypt using AES-256-GCM with the stored E2EE key and the provided `iv`.
   - The last 16 bytes of `data` are the GCM authentication tag.
3. Parse the decrypted (or plaintext) data according to the content type (see 7.4).
4. Deliver the payload to the target application (identified by bundle ID).
5. Send a `C_ACK` message.

### 7.3. C_ACK (0x23) Payload

| Offset | Size | Field  | Description                        |
| ------ | ---- | ------ | ---------------------------------- |
| 0      | 16   | msg_id | The `msg_id` from the notification |
| 16     | 1    | status | Processing result code (see below) |

**Status codes:**

| Code | Meaning                          |
| ---- | -------------------------------- |
| 0    | Success — notification delivered |
| 1    | Decryption failure               |
| 2    | Deserialization failure          |
| 3    | Expired — the notification's expiry elapsed before it could be delivered |

Acknowledgements are sent immediately if connected. If the connection is down, they are persisted to SQLite and flushed when the connection is restored.

### 7.4. Content Type: TLV Payload Format

Notification payloads use a **Type-Length-Value** encoding:

```
┌──────┬────────┬───────────────┐
│ Type │ Length │ Value          │
│ 1 B  │ 2 B   │ Length bytes   │  (repeating)
└──────┴────────┴───────────────┘
```

| Type | Key         | Value Type | Description               |
| ---- | ----------- | ---------- | ------------------------- |
| 0x01 | title       | UTF-8      | Notification title        |
| 0x02 | body        | UTF-8      | Notification body text    |
| 0x03 | sound       | UTF-8      | Sound name                |
| 0x04 | custom_data | Raw bytes  | Application-specific data |

### 7.5. C_POLL (0x22) Payload

| Offset | Size | Field    | Description                                    |
| ------ | ---- | -------- | ---------------------------------------------- |
| 0      | 8    | last_seq | Last delivered device sequence number (BE i64) |

Requests the server to re-deliver any notifications with a sequence number greater than `last_seq`. Typically sent immediately after authentication.

### 7.6. S_POLL_DONE (0x17) Payload

Empty payload (0 bytes). Signals that the server has finished delivering all queued offline messages.

---

## 8. Device Token Management

### 8.1. Concept

Each app that wishes to receive notifications needs a **device token**. This token is generated client-side, registered with the server, and then given to the app. The app passes this token to its backend service, which uses it (along with the SGN HTTP API) to send notifications.

### 8.2. Token Generation Algorithm

```
1.  K = SecureRandom(16)                     // 16 cryptographically random bytes

2.  routing_key = SHA-256(K)                 // 32 bytes

3.  salt = UTF8(server_address) + "Hello from the Skyglow Notifications developers!"
    e2ee_key = HKDF-SHA256(
        key_material  = K,
        salt          = salt,
        info          = <empty>,
        output_length = 32
    )                                         // 32 bytes

4.  padded_addr = PadRight(UTF8(server_address), 16, 0x00)
    device_token = padded_addr || K           // 32 bytes total
```

**Storage:**

| What           | Stored Locally | Sent to Server | Given to App |
| -------------- | -------------- | -------------- | ------------ |
| `K`            | Indirectly     | No             | Indirectly   |
| `routing_key`  | Yes            | Yes            | No           |
| `e2ee_key`     | Yes            | **No**         | No           |
| `device_token` | Yes            | No             | **Yes**      |

### 8.3. C_FILTER (0x2B) Payload — Active Registration Set

`C_FILTER` carries the device's **complete** `(tag, routing_key, bundle_id)` registration set. The server treats the multi-chunk transmission as a single atomic full-replace for both:

- the **routing filter** (which routing keys this device wants notifications for), and
- the **bundle binding table** (which bundle ID owns each routing key, for third-party push addressing).

`C_FILTER` is sent:

- Immediately after `S_AUTH_OK` on every connection (canonical resync).
- After any local mutation that changes the registration set (mint, mute, unmute, delete).

When the entries do not fit in a single frame, they are chunked. The server accumulates chunks until it receives one with `has_more = 0`, then atomically replaces its state. If the connection drops mid-transmission, the server MUST discard the partial buffer.

**Frame layout:**

| Offset | Size | Field   | Description                                |
| ------ | ---- | ------- | ------------------------------------------ |
| 0      | 1    | flags   | Bit 0: `has_more` (1 = more chunks follow) |
| 1      | 2    | count   | Number of entries in this chunk (BE u16)   |
| 3      | var. | entries | `count` consecutive entries (layout below) |

**Entry layout:**

| Offset | Size    | Field       | Description                                |
| ------ | ------- | ----------- | ------------------------------------------ |
| 0      | 1       | tag         | `0x01` enabled, `0x02` ignored — see below |
| 1      | 32      | routing_key | SHA-256(K) — the 32-byte routing key       |
| 33     | 2       | bid_len     | Length of bundle ID string (BE u16)        |
| 35     | bid_len | bundle_id   | Application bundle identifier (UTF-8)      |

**Per-entry tag semantics:**

| Tag    | Name    | Server behaviour                                                       | Client disposition                                                 |
| ------ | ------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `0x01` | enabled | Deliver pushes for this routing_key normally.                          | Daemon parses + dispatches to SpringBoard.                         |
| `0x02` | ignored | Should NOT deliver, but if a stale push arrives the client absorbs it. | Daemon silently ACKs SUCCESS without dispatching (defensive drop). |

The `ignored` tag is how the toggle-OFF "mute" UX is wired: the user keeps the token (instant re-enable), the server stops pushing, and any in-flight notification that crosses the filter resync gets cleanly absorbed instead of delivered. This mirrors how apsd handles its `_hashesToIgnoredTopics` set.

The client packs entries greedily and starts a new chunk when the next entry would push the frame past `SGP_MAX_PAYLOAD_LEN` (4096). A canonical empty registration set is transmitted as a single frame with `flags=0`, `count=0` and no entries — the server uses that to clear its tables.

---

## 9. Connection Lifecycle

### 9.1. Keep-Alive Mechanism

The protocol supports **bidirectional** keep-alive pings:

**Client → Server (C_PING 0x27):**

| Offset | Size | Field | Description                                       |
| ------ | ---- | ----- | ------------------------------------------------- |
| 0      | 8    | seq   | Monotonically increasing sequence number (BE i64) |

**Server → Client (S_PONG 0x16):**

| Offset | Size | Field | Description               |
| ------ | ---- | ----- | ------------------------- |
| 0      | 8    | seq   | Echo of the ping sequence |

**Server → Client (S_PING 0x1A):**

| Offset | Size | Field | Description              |
| ------ | ---- | ----- | ------------------------ |
| 0      | 8    | seq   | Server's sequence number |

**Client → Server (C_PONG 0x2A):**

| Offset | Size | Field | Description                   |
| ------ | ---- | ----- | ----------------------------- |
| 0      | 8    | seq   | Echo of the server's sequence |

The client uses an **adaptive keep-alive algorithm** with three stages:

1. **Growth** — Interval increases until a ping fails
2. **Steady** — Interval stabilizes at the maximum successful value
3. **Backoff** — Interval decreases after failures

**Pong timeout:** 15 seconds (`SGP_PONG_TIMEOUT_SEC`). If no S_PONG is received within this window, the connection is considered dead.

### 9.2. Disconnect Messages

**S_DISCONNECT (0x14):**

| Offset | Size | Field       | Description                                 |
| ------ | ---- | ----------- | ------------------------------------------- |
| 0      | 1    | reason      | Disconnect reason code (see below)          |
| 1      | 4    | retry_after | Optional: seconds before reconnect (BE u32) |

**C_DISCONNECT (0x24):**

| Offset | Size | Field  | Description            |
| ------ | ---- | ------ | ---------------------- |
| 0      | 1    | reason | Always `0x00` (normal) |

**Disconnect reason codes:**

| Code   | Name             | Class | Description                                                                                       |
| ------ | ---------------- | ----- | ------------------------------------------------------------------------------------------------- |
| `0x00` | NORMAL           | soft  | Graceful disconnect                                                                               |
| `0x01` | AUTH_FAIL        | hard  | Authentication failure (bad signature, missing credentials). Client transitions to ErrorAuth.    |
| `0x02` | PROTOCOL         | soft  | Protocol violation. Client backs off and reconnects.                                              |
| `0x03` | SERVER_ERR       | soft  | Internal server error. Client backs off and reconnects.                                           |
| `0x04` | REPLACED         | soft  | Another connection replaced this one. Client backs off and reconnects.                            |
| `0x05` | VERSION_MISMATCH | hard  | Server refuses this client because the protocol version is incompatible. **No auto-reconnect** — the user must update Skyglow and manually reload (or the daemon must be restarted). Client transitions to ErrorVersionMismatch. |

**Soft vs. hard errors:**

- A **soft** error is transient. The client schedules a reconnect via the exponential-backoff strategy described in §9.3, optionally honoring `retry_after`.
- A **hard** error is terminal. The client transitions to a configuration-error state and stops reconnecting. Only a manual configuration change (toggle disable→enable, configuration reload, or a fresh daemon launch) recovers from a hard error. Use hard errors to refuse clients that cannot succeed by retrying alone — bad credentials, incompatible protocol versions, or other states that require user/operator action.

If `retry_after` is present and non-zero on a soft error, the client should wait at least that many seconds before reconnecting.

### 9.3. Reconnection Strategy

Clients implement **exponential backoff with jitter**, bounded by a circuit breaker:

```
initial_delay = 2 seconds
max_delay     = 600 seconds
max_jitter    = 5 seconds
max_failures  = 14            // ~67 min of retrying, then stop

failures = 0
loop:
    result = connect_and_authenticate()
    if result == success:
        failures = 0
        while handle_message() == success:
            continue

    disconnect()
    failures += 1
    if failures >= max_failures:
        open_circuit()          // stop retrying; wait for an external trigger
        continue

    delay = min(initial_delay * 2^(failures - 1) + rand(0 .. max_jitter), max_delay)
    if server sent retry_after and retry_after > delay:
        delay = retry_after
    sleep(delay)
```

After `max_failures` consecutive failed attempts (~67 minutes) the client opens a **circuit breaker**: it stops retrying and waits for an external trigger — a network reachability change, a configuration reload, or a system wake from sleep — before attempting again. This bounds battery drain when the server is unreachable for an extended period.

### 9.4. S_TIME_SYNC (0x1B) Payload

| Offset | Size | Field       | Description                              |
| ------ | ---- | ----------- | ---------------------------------------- |
| 0      | 8    | server_time | Server's current Unix timestamp (BE i64) |

The client computes `offset = server_time - local_time` and applies this correction to all timestamps in login/registration messages. This handles devices with unreliable NTP (e.g., iOS 3–5 era hardware).

---

## 10. End-to-End Encryption

### 10.1. Key Derivation

Both the sending service and the receiving client independently derive the same encryption key from the shared secret `K`:

```
salt = UTF8(server_address) + "Hello from the Skyglow Notifications developers!"

e2ee_key = HKDF-SHA256(
    key_material  = K,         // 16 bytes, extracted from device_token[16:32]
    salt          = salt,
    info          = <empty>,
    output_length = 32
)
```

The sender extracts `K` from the device token (bytes 16–31) and the server address from bytes 0–15 (trimming trailing `0x00` bytes).

### 10.2. Encryption (Sender Side)

```
iv = SecureRandom(12)     // 12-byte nonce

ciphertext, tag = AES-256-GCM-Encrypt(
    key       = e2ee_key,
    iv        = iv,
    plaintext = TLV_serialize(payload),
    aad       = <none>
)

// In the S_NOTIFY frame:
//   data       = ciphertext || tag     (tag is 16 bytes)
//   iv         = iv                    (12 bytes, appended after data)
//   flags      = 0x01                  (is_encrypted = true)
```

### 10.3. Decryption (Client Side)

```
// data field contains ciphertext || 16-byte GCM auth tag

ciphertext = data[0 .. len-16]
tag        = data[len-16 .. len]

plaintext = AES-256-GCM-Decrypt(
    key        = e2ee_key,      // looked up locally by routing_key
    iv         = iv,            // from the S_NOTIFY frame (12 bytes after data)
    ciphertext = ciphertext,
    tag        = tag,
    aad        = <none>
)
```

If decryption or tag verification fails, the client acknowledges with status code `1`.

---

## 11. Server Implementation Requirements

### 11.1. Components

| Component   | Default Port | Protocol | Purpose                                            |
| ----------- | ------------ | -------- | -------------------------------------------------- |
| TCP Server  | 7373         | TLS 1.2+ | Persistent client connections, device registration |
| HTTP Server | 7878         | HTTPS    | Push submission API + cert auto-fetch (§3.4)       |
| Database    | —            | —        | Device records, queued notifications               |

Note that **device registration is performed over the TCP+TLS channel** (§5),
not over the HTTP server. The HTTP component is needed only for push
submission by notification senders and (optionally) for the cert auto-fetch
endpoint. A minimal HTTP server exposing only `GET /snd/server_cert.pem` is
sufficient for client provisioning.

### 11.2. Server Cryptographic Material

The server requires an RSA keypair for TLS and a self-signed X.509 certificate:

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout server_private_key.pem \
    -out server_public_key.pem \
    -days 7300 -nodes
```

- `server_public_key.pem` is distributed to clients via the auto-fetch endpoint (§3.4) or manual import; clients pin it for the lifetime of the profile
- `server_private_key.pem` is used by the server for TLS

### 11.3. DNS Configuration

Create a TXT record:

```
_sgn.example.com  IN  TXT  "tcp_addr=<IP> tcp_port=<TCP_PORT> http_addr=<HTTP_URL>"
```

### 11.4. Server State Per Device

The server must store:

| Field                 | Description                                                                                                                                                                |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| address               | Server-assigned device identifier (opaque UTF-8, max 255 bytes)                                                                                                            |
| public_key            | RSA-2048 public key (DER format, from C_REGISTER)                                                                                                                          |
| registrations         | Set of `(routing_key, bundle_id)` tuples — full-replace on every C_FILTER. Serves as both the routing filter and the bundle binding table for third-party push addressing. |
| last_delivered_seq    | Per-device notification sequence counter                                                                                                                                   |
| unacked_notifications | Queue of notifications not yet acknowledged                                                                                                                                |

### 11.5. Server Message Processing Summary

| When...                                | Server sends...                                                                                                                                                       |
| -------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client connects (TLS handshake done)   | S_HELLO (with server version)                                                                                                                                         |
| Client sends C_LOGIN or C_REGISTER     | S_CHALLENGE (32-byte random nonce)                                                                                                                                    |
| Client sends valid C_LOGIN_RESP        | S_AUTH_OK                                                                                                                                                             |
| Client sends valid C_REGISTER_RESP     | S_REGISTER_OK (with server version)                                                                                                                                   |
| Client sends invalid challenge resp    | S_DISCONNECT (reason: AUTH_FAIL)                                                                                                                                      |
| Push notification arrives for device   | S_NOTIFY (with routing_key, data, etc.)                                                                                                                               |
| Client sends C_FILTER chunk(s)         | (No reply.) Buffer chunks until `has_more=0`, then atomically replace the device's registration set. Discard partial buffer if the connection drops mid-transmission. |
| Client sends C_POLL                    | Re-deliver unacked notifs, then S_POLL_DONE                                                                                                                           |
| Client sends C_PING                    | S_PONG (echo sequence)                                                                                                                                                |
| Server wants to keep-alive             | S_PING (with sequence)                                                                                                                                                |
| Server needs to disconnect             | S_DISCONNECT (with reason + optional retry)                                                                                                                           |
| Clock drift detected                   | S_TIME_SYNC (server's Unix timestamp)                                                                                                                                 |
| Another client connects with same addr | S_DISCONNECT (reason: REPLACED) to old conn                                                                                                                           |

### 11.6. Challenge Verification

When verifying C_LOGIN_RESP or C_REGISTER_RESP:

1. Reconstruct `digest = SHA-256(nonce || address_utf8 || timestamp_be64)`
2. Verify the RSA-PSS signature using the client's stored public key
3. Verify that `timestamp` is within ±300 seconds of the server's current time
4. If `address` is unknown (for C_LOGIN), reject with S_DISCONNECT

### 11.7. Payload Bounds Validation

The server should enforce the same payload bounds the client expects:

| Message Type    | Min Size | Max Size |
| --------------- | -------- | -------- |
| S_HELLO         | 4        | 4        |
| S_CHALLENGE     | 32       | 32       |
| S_AUTH_OK       | 0        | 0        |
| S_NOTIFY        | 70       | 4096     |
| S_DISCONNECT    | 1        | 5        |
| S_PONG          | 8        | 8        |
| S_POLL_DONE     | 0        | 0        |
| S_REGISTER_OK   | 4        | 4        |
| S_REGISTER_FAIL | 1        | 258      |
| S_PING          | 8        | 8        |
| S_TIME_SYNC     | 8        | 8        |

---

## 12. Security Considerations

1. **TLS with certificate pinning** prevents man-in-the-middle attacks. The client trusts only the specific server certificate obtained during registration.

2. **RSA-PSS challenge-response authentication** provides strong mutual verification. The client proves possession of the private key corresponding to the public key registered with the server.

3. **Timestamp validation** on challenges prevents replay attacks (300-second tolerance window).

4. **End-to-end encryption** ensures the server operator cannot read notification payloads. The server only sees opaque routing keys and ciphertext.

5. **Routing key is a one-way hash** of the secret `K`. The server never learns `K` and cannot derive the E2EE key.

6. **Device token structure** embeds the server address, enabling clients to route tokens to the correct server in a multi-server (federated) deployment.

7. **SIGPIPE handling** — clients MUST ignore SIGPIPE to prevent process termination when the server drops the connection unexpectedly.

8. **Key material zeroing** — the client zeros all private key material in memory before freeing, using volatile writes to prevent compiler dead-store elimination.

9. **Clock skew correction** via S_TIME_SYNC prevents authentication failures on devices with drifted system clocks.

---

## 13. Implementation Checklist

For implementors building a compatible **server**:

- [ ] TLS 1.2+ server with configurable certificate
- [ ] Binary frame parser (8-byte header + payload)
- [ ] RSA-PSS-SHA256 signature verification
- [ ] SHA-256 for routing key verification
- [ ] AES-256-GCM encryption for E2EE payloads (optional, for server-originated notifications)
- [ ] TLV serializer for notification payloads
- [ ] Persistent storage for device records, routing keys, and notification queues
- [ ] Per-device sequence counter for notifications
- [ ] Challenge nonce generation (32 bytes, cryptographically random)
- [ ] Bidirectional keep-alive (S_PING/C_PONG and C_PING/S_PONG)
- [ ] Connection replacement detection (S_DISCONNECT with REPLACED reason)
- [ ] DNS TXT record configuration
- [ ] HTTP API for push submission (separate service) — registration itself is performed over the TCP channel (§5)
- [ ] `GET /snd/server_cert.pem` on the HTTP server, returning the same PEM the TLS listener presents (enables client auto-fetch, §3.4)

---

## Appendix A: Device Token Binary Layout

```
Byte Offset   Length   Content
──────────────────────────────────────────────────
0             16       Server address (UTF-8, right-padded with 0x00)
16            16       K (cryptographic random secret)
──────────────────────────────────────────────────
Total:        32 bytes
```

The token is opaque to the receiving application. A sending service parses it as follows:

1. Read bytes 0–15 and trim trailing `0x00` bytes → server address
2. Use the server address to resolve the SGN server endpoint via DNS TXT records
3. Read bytes 16–31 → secret `K`
4. Derive `routing_key = SHA-256(K)` to identify the device when submitting notifications
5. Derive `e2ee_key` using HKDF-SHA256 (see Section 10.1) if sending encrypted payloads

## Appendix B: Wire Examples

### B.1. Frame Header

```
53 02 20 00 00 00 00 0E       Magic=0x53, Version=0x02, Type=C_LOGIN(0x20),
                               Reserved=0x00, PayloadLen=14
```

### B.2. C_LOGIN Payload

```
00 24                          addr_len = 36
61 62 63 64 65 66 ... (36 B)   address = "abcdefgh-1234-5678-9abc-def012345678"
00 00 01 8E 2A 3B 4C 5D        timestamp (BE i64)
00 00 00 02                    version = 2 (BE u32)
```

### B.3. S_NOTIFY Payload (Encrypted)

```
[32 bytes routing_key]
[16 bytes msg_id]
[8 bytes seq (BE i64)]
[8 bytes expires_at (BE i64)]
01                             flags: is_encrypted = 1
00                             content_type
00 00 00 40                    data_len = 64 (BE u32)
[64 bytes: ciphertext(48) || GCM tag(16)]
[12 bytes: IV]
```

### B.4. C_ACK Payload

```
[16 bytes msg_id]
00                             status = 0 (success)
```
