# Skyglow Notifications Protocol Specification

**Version:** 2 (`SGP_VERSION = 0x02`)  
**Last Updated:** March 2026

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

| Key         | Description                                        | Required |
|-------------|----------------------------------------------------|----------|
| `tcp_addr`  | IPv4 address of the TCP protocol server            | Yes      |
| `tcp_port`  | Port number of the TCP protocol server (TLS)       | Yes      |
| `http_addr` | Base URL of the HTTP registration/push API         | No       |

**Important:** `tcp_port` must point to the TLS-enabled TCP protocol listener, **not** the HTTP API port. These are distinct services running on different ports.

### 2.4. DNS Caching

Clients cache resolved DNS records locally (SQLite) and use cached values on subsequent startups. The cache TTL is **1 hour** (3600 seconds). The cache is refreshed asynchronously in the background after a successful connection.

---

## 3. Transport Layer

### 3.1. TLS Connection

All TCP protocol communication occurs over a TLS connection. The server uses a self-signed X.509 certificate. The client receives the server's public certificate during initial HTTP registration (stored locally) and uses **certificate pinning** — only the pinned certificate is trusted.

- **Protocol:** TLS 1.2+ (SSLv2, SSLv3, TLS 1.0, and TLS 1.1 are explicitly disabled)
- **Certificate validation:** Pinned server certificate only
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

| Field          | Size    | Description                                               |
|----------------|---------|-----------------------------------------------------------|
| Magic          | 1 byte  | Always `0x53` (ASCII `S`)                                 |
| Version        | 1 byte  | Protocol version, currently `0x02`                        |
| Type           | 1 byte  | Message type identifier (see Section 4)                   |
| Reserved       | 1 byte  | Must be `0x00`. Non-zero values cause a protocol error.   |
| Payload Length | 4 bytes | Unsigned 32-bit integer, **big-endian** (network order)   |
| Payload        | N bytes | Type-specific binary data. Max `4096` bytes.              |

**Header size:** 8 bytes fixed.  
**Maximum payload:** 4096 bytes (`SGP_MAX_PAYLOAD_LEN`).

### 3.3. Byte Order

All multi-byte integers in payloads are encoded in **big-endian** (network byte order). This applies to:
- The 4-byte payload length in the header
- All `int64_t` timestamps and sequence numbers (8 bytes)
- All `uint32_t` version numbers and data lengths (4 bytes)
- All `uint16_t` string lengths (2 bytes)

---

## 4. Message Types

### 4.1. Server → Client Messages (`0x1_`)

| Type   | Name              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| `0x10` | S_HELLO           | Server greeting after TLS handshake                  |
| `0x11` | S_CHALLENGE       | Authentication challenge nonce                       |
| `0x12` | S_AUTH_OK         | Authentication successful                            |
| `0x13` | S_NOTIFY          | Incoming push notification                           |
| `0x14` | S_DISCONNECT      | Server is closing the connection                     |
| `0x15` | S_TOKEN_ACK       | Acknowledgment of device token registration          |
| `0x16` | S_PONG            | Response to client keep-alive ping                   |
| `0x17` | S_POLL_DONE       | All offline messages have been delivered              |
| `0x18` | S_REGISTER_OK     | First-time device registration succeeded             |
| `0x19` | S_REGISTER_FAIL   | First-time device registration failed                |
| `0x1A` | S_PING            | Server-initiated keep-alive ping                     |
| `0x1B` | S_TIME_SYNC       | Clock synchronization message                        |

### 4.2. Client → Server Messages (`0x2_`)

| Type   | Name              | Description                                          |
|--------|-------------------|------------------------------------------------------|
| `0x20` | C_LOGIN           | Login handshake initiation                           |
| `0x21` | C_LOGIN_RESP      | Response to authentication challenge                 |
| `0x22` | C_POLL            | Request offline (undelivered) notifications          |
| `0x23` | C_ACK             | Acknowledge receipt of a notification                |
| `0x24` | C_DISCONNECT      | Client is closing the connection                     |
| `0x25` | C_REG_TOKEN       | Register a device token (routing key) for an app     |
| `0x27` | C_PING            | Client-initiated keep-alive ping                     |
| `0x28` | C_REGISTER        | First-time device registration request               |
| `0x29` | C_REGISTER_RESP   | Response to first-time registration challenge        |
| `0x2A` | C_PONG            | Response to server keep-alive ping                   |
| `0x2B` | C_FILTER          | Active routing key filter (chunked)                  |

---

## 5. First-Time Device Registration

Before a device can authenticate, it must register with the server to obtain an identity. This is a one-time process.

### 5.1. Sequence

```
Client                                              Server
  │                                                    │
  │──────────── [C_REGISTER 0x28] ────────────────────►│
  │  { address, public_key_DER, timestamp, version }   │
  │                                                    │
  │◄───────────── [S_CHALLENGE 0x11] ─────────────────│
  │  { 32-byte nonce }                                 │
  │                                                    │
  │──────────── [C_REGISTER_RESP 0x29] ───────────────►│
  │  { timestamp, RSA-PSS signature }                  │
  │                                                    │
  │◄─────── [S_REGISTER_OK 0x18] or [S_REGISTER_FAIL] │
  │                                                    │
```

### 5.2. C_REGISTER (0x28) Payload

| Offset | Size         | Field          | Description                                    |
|--------|--------------|----------------|------------------------------------------------|
| 0      | 2            | addr_len       | Length of the device address string (BE u16)    |
| 2      | addr_len     | address        | UUID-formatted device address (UTF-8)          |
| 2+AL   | 2            | pubkey_len     | Length of DER-encoded public key (BE u16)       |
| 4+AL   | pubkey_len   | public_key     | RSA-2048 public key in DER format (`i2d_RSA_PUBKEY`) |
| 4+AL+PL| 8            | timestamp      | Current Unix time, corrected for clock skew (BE i64) |
| 12+AL+PL| 4           | version        | Protocol version `0x02` (BE u32)               |

The client generates:
- A **UUID v4** as the device address
- An **RSA-2048** keypair — the public key is sent to the server, the private key is stored locally

### 5.3. S_REGISTER_OK (0x18) Payload

| Offset | Size | Field          | Description                                |
|--------|------|----------------|--------------------------------------------|
| 0      | 4    | server_version | Server's protocol version (BE u32)         |

### 5.4. S_REGISTER_FAIL (0x19) Payload

| Offset | Size       | Field      | Description                         |
|--------|------------|------------|-------------------------------------|
| 0      | 1          | code       | Rejection reason code (u8)          |
| 1      | 2          | reason_len | Length of reason string (BE u16)    |
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

| Offset | Size | Field          | Description                    |
|--------|------|----------------|--------------------------------|
| 0      | 4    | server_version | Server's protocol version (BE u32) |

Sent by the server immediately after the TLS handshake completes.

### 6.3. C_LOGIN (0x20) Payload

| Offset | Size     | Field     | Description                                     |
|--------|----------|-----------|-------------------------------------------------|
| 0      | 2        | addr_len  | Length of address string (BE u16)                |
| 2      | addr_len | address   | The client's registered UUID address (UTF-8)     |
| 2+AL   | 8        | timestamp | Current Unix time, corrected for clock skew (BE i64) |
| 10+AL  | 4        | version   | Protocol version `0x02` (BE u32)                 |

### 6.4. S_CHALLENGE (0x11) Payload

| Offset | Size | Field | Description                               |
|--------|------|-------|-------------------------------------------|
| 0      | 32   | nonce | Server-generated cryptographic nonce      |

The same S_CHALLENGE message type is used for both login and first-time registration flows.

### 6.5. C_LOGIN_RESP (0x21) / C_REGISTER_RESP (0x29) Payload

Both response types use the same payload format:

| Offset | Size    | Field    | Description                                                |
|--------|---------|----------|------------------------------------------------------------|
| 0      | 8       | timestamp| The timestamp from the original C_LOGIN/C_REGISTER (BE i64)|
| 8      | 2       | sig_len  | Length of RSA-PSS signature (BE u16)                       |
| 10     | sig_len | signature| RSA-PSS-SHA256 signature (see 6.6)                        |

### 6.6. RSA-PSS Signature Scheme

The client produces the signature as follows:

1. Compute `digest = SHA-256(nonce || address_utf8 || timestamp_be64)`
2. Apply RSA-PSS padding with `SHA-256` as both the hash and MGF1 hash, salt length = hash length (32)
3. Sign with `RSA_private_encrypt(padded_message, RSA_NO_PADDING)`

The server verifies this signature using the client's stored public key.

### 6.7. S_AUTH_OK (0x12) Payload

Empty payload (0 bytes). Confirms the client has authenticated.

### 6.8. Clock Skew Correction

The server may send `S_TIME_SYNC (0x1B)` at any time, containing an 8-byte big-endian Unix timestamp. The client computes `offset = server_time - local_time` and applies this correction to all subsequent timestamps sent in C_LOGIN and C_REGISTER messages. This handles iOS devices with drifted clocks. The server's challenge window is **300 seconds** (`SGP_CHALLENGE_WINDOW_SEC`).

---

## 7. Notification Delivery

### 7.1. S_NOTIFY (0x13) Payload Layout

```
┌──────────────┬──────────┬──────┬────────────┬───────┬──────────────┬──────────┬──────────────┬──────────┐
│ routing_key  │ msg_id   │ seq  │ expires_at │ flags │ content_type │ data_len │ data         │ [iv]     │
│ 32 bytes     │ 16 bytes │ 8 B  │ 8 B        │ 1 B   │ 1 B          │ 4 B (BE) │ data_len B   │ 12 B     │
└──────────────┴──────────┴──────┴────────────┴───────┴──────────────┴──────────┴──────────────┴──────────┘
```

| Offset | Size      | Field        | Description                                           |
|--------|-----------|--------------|-------------------------------------------------------|
| 0      | 32        | routing_key  | SHA-256 hash of the token secret K                    |
| 32     | 16        | msg_id       | Unique notification ID (raw 16 bytes, UUID)           |
| 48     | 8         | seq          | Server-assigned per-device sequence number (BE i64)   |
| 56     | 8         | expires_at   | Expiration timestamp (BE i64), 0 = no expiry          |
| 64     | 1         | flags        | Bit 0: `is_encrypted` (1 = E2EE payload)             |
| 65     | 1         | content_type | Payload format identifier (see 7.4)                   |
| 66     | 4         | data_len     | Length of the data field in bytes (BE u32)             |
| 70     | data_len  | data         | Notification payload (plaintext or ciphertext+tag)    |
| 70+DL  | 12        | iv           | AES-GCM IV (**only present when `is_encrypted = 1`**) |

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

| Offset | Size | Field    | Description                                |
|--------|------|----------|--------------------------------------------|
| 0      | 16   | msg_id   | The `msg_id` from the notification         |
| 16     | 1    | status   | Processing result code (see below)         |

**Status codes:**

| Code | Meaning                             |
|------|-------------------------------------|
| 0    | Success — notification delivered    |
| 1    | Decryption failure                  |
| 2    | Deserialization failure             |

Acknowledgements are sent immediately if connected. If the connection is down, they are persisted to SQLite and flushed when the connection is restored.

### 7.4. Content Type: TLV Payload Format

Notification payloads use a **Type-Length-Value** encoding:

```
┌──────┬────────┬───────────────┐
│ Type │ Length │ Value          │
│ 1 B  │ 2 B   │ Length bytes   │  (repeating)
└──────┴────────┴───────────────┘
```

| Type | Key           | Value Type | Description                  |
|------|---------------|------------|------------------------------|
| 0x01 | title        | UTF-8      | Notification title           |
| 0x02 | body         | UTF-8      | Notification body text       |
| 0x03 | sound        | UTF-8      | Sound name                   |
| 0x04 | custom_data  | Raw bytes  | Application-specific data    |

### 7.5. C_POLL (0x22) Payload

| Offset | Size | Field    | Description                                              |
|--------|------|----------|----------------------------------------------------------|
| 0      | 8    | last_seq | Last delivered device sequence number (BE i64)           |

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
|----------------|----------------|----------------|--------------|
| `K`            | Indirectly     | No             | Indirectly   |
| `routing_key`  | Yes            | Yes            | No           |
| `e2ee_key`     | Yes            | **No**         | No           |
| `device_token` | Yes            | No             | **Yes**      |

### 8.3. C_REG_TOKEN (0x25) Payload

| Offset | Size     | Field       | Description                                |
|--------|----------|-------------|--------------------------------------------|
| 0      | 32       | routing_key | SHA-256(K) — the 32-byte routing key       |
| 32     | 2        | bid_len     | Length of bundle ID string (BE u16)        |
| 34     | bid_len  | bundle_id   | Application bundle identifier (UTF-8)      |

The client blocks for up to **5 seconds** waiting for S_TOKEN_ACK before considering the registration failed.

### 8.4. S_TOKEN_ACK (0x15) Payload

| Offset | Size     | Field       | Description                                |
|--------|----------|-------------|--------------------------------------------|
| 0      | 32       | routing_key | Echo of the registered routing key         |
| 32     | 2        | bid_len     | Length of bundle ID string (BE u16)        |
| 34     | bid_len  | bundle_id   | The bundle ID that was registered (UTF-8)  |

### 8.5. C_FILTER (0x2B) Payload — Active Topic Filter

Sent after authentication to inform the server which routing keys the client is currently interested in. This allows the server to drop notifications for unsubscribed topics.

The filter is sent in chunks when there are too many keys for a single frame:

| Offset | Size         | Field     | Description                                    |
|--------|--------------|-----------|------------------------------------------------|
| 0      | 1            | flags     | Bit 0: `has_more` (1 = more chunks follow)     |
| 1      | 2            | count     | Number of routing keys in this chunk (BE u16)  |
| 3      | count × 32   | keys      | Concatenated 32-byte routing keys              |

Maximum keys per chunk: `(4096 - 3) / 32 = 127`.

---

## 9. Connection Lifecycle

### 9.1. Keep-Alive Mechanism

The protocol supports **bidirectional** keep-alive pings:

**Client → Server (C_PING 0x27):**

| Offset | Size | Field | Description                                |
|--------|------|-------|--------------------------------------------|
| 0      | 8    | seq   | Monotonically increasing sequence number (BE i64) |

**Server → Client (S_PONG 0x16):**

| Offset | Size | Field | Description                    |
|--------|------|-------|--------------------------------|
| 0      | 8    | seq   | Echo of the ping sequence      |

**Server → Client (S_PING 0x1A):**

| Offset | Size | Field | Description                    |
|--------|------|-------|--------------------------------|
| 0      | 8    | seq   | Server's sequence number       |

**Client → Server (C_PONG 0x2A):**

| Offset | Size | Field | Description                    |
|--------|------|-------|--------------------------------|
| 0      | 8    | seq   | Echo of the server's sequence  |

The client uses an **adaptive keep-alive algorithm** with three stages:

1. **Growth** — Interval increases until a ping fails
2. **Steady** — Interval stabilizes at the maximum successful value
3. **Backoff** — Interval decreases after failures

**Pong timeout:** 15 seconds (`SGP_PONG_TIMEOUT_SEC`). If no S_PONG is received within this window, the connection is considered dead.

### 9.2. Disconnect Messages

**S_DISCONNECT (0x14):**

| Offset | Size | Field       | Description                              |
|--------|------|-------------|------------------------------------------|
| 0      | 1    | reason      | Disconnect reason code (see below)       |
| 1      | 4    | retry_after | Optional: seconds before reconnect (BE u32) |

**C_DISCONNECT (0x24):**

| Offset | Size | Field  | Description                    |
|--------|------|--------|--------------------------------|
| 0      | 1    | reason | Always `0x00` (normal)         |

**Disconnect reason codes:**

| Code   | Name            | Description                                      |
|--------|-----------------|--------------------------------------------------|
| `0x00` | NORMAL          | Graceful disconnect                              |
| `0x01` | AUTH_FAIL       | Authentication failure                           |
| `0x02` | PROTOCOL        | Protocol violation                               |
| `0x03` | SERVER_ERR      | Internal server error                            |
| `0x04` | REPLACED        | Another connection replaced this one             |

If `retry_after` is present and non-zero, the client should wait at least that many seconds before reconnecting.

### 9.3. Reconnection Strategy

Clients implement **exponential backoff**:

```
backoff = 1 second (initial)
MAX_BACKOFF = 256 seconds

loop:
    result = connect_and_authenticate()
    if result == success:
        reset backoff to 1
        while handle_message() == success:
            continue
    
    disconnect()
    if server sent retry_after:
        sleep(retry_after)
    else:
        sleep(backoff)
        backoff = min(backoff * 2, MAX_BACKOFF)
```

The client also detects **rapid disconnection loops** and disables itself to prevent resource exhaustion.

### 9.4. S_TIME_SYNC (0x1B) Payload

| Offset | Size | Field       | Description                              |
|--------|------|-------------|------------------------------------------|
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

| Component   | Default Port | Protocol | Purpose                              |
|-------------|-------------|----------|--------------------------------------|
| TCP Server  | 7373        | TLS 1.2+ | Persistent client connections        |
| HTTP Server | 7878        | HTTP(S)  | Registration API, push submission    |
| Database    | —           | —        | Device records, queued notifications |

### 11.2. Server Cryptographic Material

The server requires an RSA keypair for TLS and a self-signed X.509 certificate:

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout server_private_key.pem \
    -out server_public_key.pem \
    -days 7300 -nodes
```

- `server_public_key.pem` is distributed to clients during HTTP registration (used for TLS certificate pinning)
- `server_private_key.pem` is used by the server for TLS

### 11.3. DNS Configuration

Create a TXT record:

```
_sgn.example.com  IN  TXT  "tcp_addr=<IP> tcp_port=<TCP_PORT> http_addr=<HTTP_URL>"
```

### 11.4. Server State Per Device

The server must store:

| Field                | Description                                                    |
|----------------------|----------------------------------------------------------------|
| address              | UUID device identifier                                         |
| public_key           | RSA-2048 public key (DER format, from C_REGISTER)              |
| routing_keys         | Set of 32-byte routing keys → bundle ID mappings               |
| active_filter        | Current set of routing keys the client is interested in        |
| last_delivered_seq   | Per-device notification sequence counter                       |
| unacked_notifications| Queue of notifications not yet acknowledged                    |

### 11.5. Server Message Processing Summary

| When...                              | Server sends...                              |
|--------------------------------------|----------------------------------------------|
| Client connects (TLS handshake done) | S_HELLO (with server version)                |
| Client sends C_LOGIN or C_REGISTER   | S_CHALLENGE (32-byte random nonce)           |
| Client sends valid C_LOGIN_RESP      | S_AUTH_OK                                    |
| Client sends valid C_REGISTER_RESP   | S_REGISTER_OK (with server version)          |
| Client sends invalid challenge resp  | S_DISCONNECT (reason: AUTH_FAIL)             |
| Push notification arrives for device | S_NOTIFY (with routing_key, data, etc.)      |
| Client sends C_REG_TOKEN             | S_TOKEN_ACK (echo routing_key + bundle_id)   |
| Client sends C_POLL                  | Re-deliver unacked notifs, then S_POLL_DONE  |
| Client sends C_PING                  | S_PONG (echo sequence)                       |
| Server wants to keep-alive           | S_PING (with sequence)                       |
| Server needs to disconnect           | S_DISCONNECT (with reason + optional retry)  |
| Clock drift detected                 | S_TIME_SYNC (server's Unix timestamp)        |
| Another client connects with same addr| S_DISCONNECT (reason: REPLACED) to old conn |

### 11.6. Challenge Verification

When verifying C_LOGIN_RESP or C_REGISTER_RESP:

1. Reconstruct `digest = SHA-256(nonce || address_utf8 || timestamp_be64)`
2. Verify the RSA-PSS signature using the client's stored public key
3. Verify that `timestamp` is within ±300 seconds of the server's current time
4. If `address` is unknown (for C_LOGIN), reject with S_DISCONNECT

### 11.7. Payload Bounds Validation

The server should enforce the same payload bounds the client expects:

| Message Type     | Min Size | Max Size |
|------------------|----------|----------|
| S_HELLO          | 4        | 4        |
| S_CHALLENGE      | 32       | 32       |
| S_AUTH_OK        | 0        | 0        |
| S_NOTIFY         | 70       | 4096     |
| S_DISCONNECT     | 1        | 5        |
| S_TOKEN_ACK      | 35       | 289      |
| S_PONG           | 8        | 8        |
| S_POLL_DONE      | 0        | 0        |
| S_REGISTER_OK    | 4        | 4        |
| S_REGISTER_FAIL  | 1        | 258      |
| S_PING           | 8        | 8        |
| S_TIME_SYNC      | 8        | 8        |

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
- [ ] HTTP API for registration and push submission (separate service)

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
