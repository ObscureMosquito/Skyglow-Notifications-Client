# Skyglow Notifications Protocol Specification

**Version:** 1.0.0  
**Last Updated:** February 2026

---

## 1. Overview

Skyglow Notifications (SGN) is a decentralized push notification protocol designed as an alternative to Apple Push Notification Service (APNS). It enables third-party notification delivery to iOS devices via a persistent TLS connection between a client daemon and a server.

The system consists of three layers:

1. **Service Discovery** — DNS TXT record resolution to locate the server
2. **TCP Protocol** — A persistent TLS connection carrying length-prefixed binary plist messages for authentication, notification delivery, and device token management
3. **HTTP API** — Used during initial device registration and by notification senders to submit push messages (out of scope for this document)

The protocol is designed to be lightweight, suitable for low-power devices (including iOS 6 era hardware), and supports end-to-end encryption of notification payloads.

---

## 2. Service Discovery

### 2.1. Server Address

Each SGN server has a **server address** — a domain string of **at most 16 characters** (e.g., `skyglow.es`). This address is stored on the client during registration and is embedded into device tokens.

### 2.2. DNS TXT Record Resolution

The client resolves the server's IP address and port at startup via DNS TXT records. The resolution tries multiple record names in priority order:

| Priority | DNS Name                          | Example                       |
|----------|-----------------------------------|-------------------------------|
| 1        | `_sgn.sgn.<server_address>`       | `_sgn.sgn.skyglow.es`        |
| 2        | `_sgn._tcp.<server_address>`      | `_sgn._tcp.skyglow.es`       |
| 3        | `_sgn.<server_address>`           | `_sgn.skyglow.es`            |

The first record that returns results is used. Resolution stops after the first successful lookup.

### 2.3. TXT Record Format

The TXT record contains space-separated key-value pairs:

```
"tcp_addr=143.47.32.233 tcp_port=7373 http_addr=https://sgn.example.com"
```

| Key         | Description                                        | Required |
|-------------|----------------------------------------------------|----------|
| `tcp_addr`  | IPv4 address of the TCP protocol server             | Yes      |
| `tcp_port`  | Port number of the TCP protocol server (TLS)        | Yes      |
| `http_addr` | Base URL of the HTTP registration/push API          | No       |

**Important:** `tcp_port` must point to the TLS-enabled TCP protocol listener, **not** the HTTP API port. These are distinct services running on different ports.

### 2.4. DNS Caching

Clients SHOULD cache resolved DNS records locally (e.g., in SQLite) and use cached values on subsequent startups. A cache TTL of **1 hour** is recommended. The cache should be refreshed in the background after a successful connection.

---

## 3. Transport Layer

### 3.1. TLS Connection

All TCP protocol communication occurs over a TLS connection. The server uses a **self-signed X.509 certificate**. The client receives the server's public certificate during initial HTTP registration (stored locally) and uses **certificate pinning** — only the pinned certificate is trusted.

- **Protocol:** TLS 1.0+ (SSLv2 and SSLv3 MUST be disabled)
- **Certificate validation:** Pinned server certificate only
- **Connection model:** Single persistent long-lived connection; client reconnects with exponential backoff on failure

### 3.2. Message Framing

All messages in both directions use identical framing:

```
┌──────────────────┬──────────────────────────────┐
│  Length (4 bytes) │  Payload (N bytes)           │
│  big-endian u32  │  Binary plist                │
└──────────────────┴──────────────────────────────┘
```

1. **Length prefix:** 4 bytes, unsigned 32-bit integer in **network byte order** (big-endian), containing the byte length of the payload that follows.
2. **Payload:** An Apple Binary Property List (`bplist00` format, aka `NSPropertyListBinaryFormat_v1_0`). The root object is always a **dictionary**.

Every message dictionary MUST contain a `$type` key (integer) indicating the message type. Additional keys depend on the message type.

### 3.3. Plist Serialization

The wire format uses Apple's Binary Property List format (magic bytes `bplist00`). Implementations on non-Apple platforms must use a compatible binary plist serializer/deserializer. The following plist value types are used in this protocol:

| Plist Type | Usage                                           |
|------------|-------------------------------------------------|
| Integer    | `$type` field, status codes, numeric values     |
| String     | Addresses, nonces, timestamps, bundle IDs       |
| Data       | Raw bytes (keys, tokens, ciphertext, IVs)       |
| Boolean    | Flags such as `is_encrypted`                    |
| Dictionary | Root object of every message, nested payloads   |

---

## 4. Message Types

### 4.1. Server → Client Messages

| `$type` | Name                       | Description                                  |
|---------|----------------------------|----------------------------------------------|
| 0       | Hello                      | Server greeting after TLS handshake          |
| 1       | LoginChallenge             | RSA-encrypted challenge for authentication   |
| 2       | ReceiveNotification        | Incoming push notification                   |
| 3       | AuthenticationSuccessful   | Login completed successfully                 |
| 4       | ServerDisconnect           | Server is closing the connection             |
| 5       | DeviceTokenRegisterAck     | Acknowledgment of device token registration  |

### 4.2. Client → Server Messages

| `$type` | Name                       | Description                                  |
|---------|----------------------------|----------------------------------------------|
| 0       | LoginRequest               | Initial login with address and version       |
| 1       | LoginChallengeResponse     | Response to the server's challenge           |
| 2       | PollUnackedNotifications   | Request re-delivery of missed notifications  |
| 3       | AckNotification            | Acknowledge receipt of a notification        |
| 4       | ClientDisconnect           | Client is closing the connection             |
| 5       | RegisterDeviceToken        | Register a routing key for an app            |
| 6       | SendFeedback               | Report a token as invalid / unsubscribe      |

---

## 5. Authentication Flow

Authentication uses a **challenge-response** scheme with RSA public-key cryptography. The client possesses an RSA private key; the server holds the corresponding public key (exchanged during initial HTTP registration).

### 5.1. Sequence Diagram

```
Client                                              Server
  │                                                    │
  │◄───────────── [S→C type 0] Hello ─────────────────│
  │                                                    │
  │────────────── [C→S type 0] LoginRequest ──────────►│
  │  { address, version, lang }                        │
  │                                                    │
  │◄───────────── [S→C type 1] LoginChallenge ────────│
  │  { challenge: RSA_OAEP(address,nonce,ts) }         │
  │                                                    │
  │────────────── [C→S type 1] LoginChallengeResponse ►│
  │  { nonce, timestamp }                              │
  │                                                    │
  │◄───────────── [S→C type 3] AuthenticationSuccessful│
  │                                                    │
  │────────────── [C→S type 2] PollUnackedNotifications►
  │  { }                                               │
  │                                                    │
  ▼                                                    ▼
       (persistent bidirectional connection)
```

### 5.2. Hello (Server → Client, type 0)

Sent by the server immediately after the TLS handshake completes. Signals that the server is ready to receive a login request.

**Fields:** Only `$type`.

### 5.3. LoginRequest (Client → Server, type 0)

The client sends its identity and protocol metadata.

| Key       | Type   | Description                                            |
|-----------|--------|--------------------------------------------------------|
| `address` | String | The client's registered address (e.g., `user@sgn.es`) |
| `version` | String | Protocol version string (currently `"1.0.0"`)          |
| `lang`    | String | BCP-47 language tag (e.g., `"en"`, `"es"`)             |

### 5.4. LoginChallenge (Server → Client, type 1)

The server encrypts a challenge string with the client's **RSA public key** using **RSA-OAEP** padding and sends the ciphertext.

| Key         | Type | Description                        |
|-------------|------|------------------------------------|
| `challenge` | Data | RSA-OAEP encrypted challenge blob  |

**Challenge plaintext format** — a comma-separated UTF-8 string:

```
<address>,<nonce>,<timestamp>
```

| Field       | Description                                                  |
|-------------|--------------------------------------------------------------|
| `address`   | The client's address (MUST match what the client sent)       |
| `nonce`     | A server-generated random string (opaque to the client)      |
| `timestamp` | Unix epoch as a decimal string (seconds since 1970-01-01)    |

### 5.5. LoginChallengeResponse (Client → Server, type 1)

The client decrypts the challenge using its **RSA private key** and validates:

1. The `address` field matches its own registered address
2. The `timestamp` is within an acceptable window (RECOMMENDED: -5 minutes to +1 minute from current time)

If valid, the client echoes back the nonce and timestamp:

| Key         | Type   | Description                                |
|-------------|--------|--------------------------------------------|
| `nonce`     | String | The nonce extracted from the decrypted challenge |
| `timestamp` | String | The timestamp extracted from the decrypted challenge |

### 5.6. AuthenticationSuccessful (Server → Client, type 3)

Confirms the client has authenticated. No additional fields beyond `$type`.

Upon receiving this message, the client SHOULD immediately send `PollUnackedNotifications` to retrieve any queued notifications.

---

## 6. Notification Delivery

### 6.1. ReceiveNotification (Server → Client, type 2)

| Key             | Type    | Presence          | Description                                        |
|-----------------|---------|-------------------|----------------------------------------------------|
| `routing_key`   | Data    | Always            | 32-byte routing key identifying the target app     |
| `message_id`    | String  | Always            | Unique notification ID (UUID string)               |
| `is_encrypted`  | Boolean | Always            | `true` if the payload uses E2EE                    |
| `data`          | Dict    | When unencrypted  | The notification payload dictionary                |
| `data_type`     | String  | When encrypted    | `"json"` or `"plist"` — serialization format       |
| `ciphertext`    | Data    | When encrypted    | AES-256-GCM ciphertext with appended 16-byte tag   |
| `iv`            | Data    | When encrypted    | AES-256-GCM initialization vector                  |

### 6.2. Processing Steps

1. Look up `routing_key` in the local database to find the associated **bundle ID** and **E2EE key**.
2. If `is_encrypted` is `true`:
   - Decrypt `ciphertext` using AES-256-GCM with the stored E2EE key and the provided `iv`. The last 16 bytes of the `ciphertext` field are the GCM authentication tag.
   - Deserialize the plaintext according to `data_type` (`"json"` → JSON dictionary, `"plist"` → binary plist dictionary).
3. If `is_encrypted` is `false`:
   - Use `data` directly as the notification payload.
4. Deliver the payload to the target application (identified by bundle ID).
5. Send an `AckNotification` message.

### 6.3. AckNotification (Client → Server, type 3)

| Key            | Type    | Description                                |
|----------------|---------|--------------------------------------------|
| `notification` | String  | The `message_id` from the notification     |
| `status`       | Integer | Processing result code (see below)         |

**Status codes:**

| Code | Meaning                             |
|------|-------------------------------------|
| 0    | Success — notification delivered    |
| 1    | Decryption failure                  |
| 2    | Deserialization failure             |

### 6.4. PollUnackedNotifications (Client → Server, type 2)

Requests the server to re-deliver any notifications not yet acknowledged. Typically sent immediately after authentication. Can be sent at any time.

**Fields:** Only `$type` (empty dictionary otherwise).

---

## 7. Device Token Management

### 7.1. Concept

Each app that wishes to receive notifications needs a **device token**. This token is generated client-side, registered with the server, and then given to the app. The app passes this token to its backend service, which uses it (along with the SGN HTTP API) to send notifications.

The device token is a 32-byte opaque blob that encodes the server address and a cryptographic secret.

### 7.2. Token Generation Algorithm

```
1.  K = SecureRandom(16)                // 16 cryptographically random bytes

2.  routing_key = SHA-256(K)            // 32 bytes

3.  salt = UTF8(server_address) + "Hello from the Skyglow Notifications developers!"
    e2ee_key = HKDF-SHA256(
        key_material = K,
        salt         = salt,
        info         = <empty>,
        output_length = 32
    )                                    // 32 bytes

4.  padded_addr = PadRight(UTF8(server_address), 16, 0x00)
    device_token = padded_addr || K      // 32 bytes total
```

**Storage:**

| What           | Stored Locally | Sent to Server | Given to App |
|----------------|----------------|----------------|--------------|
| `K`            | Indirectly (in token) | No       | Indirectly (in token) |
| `routing_key`  | Yes            | Yes            | No           |
| `e2ee_key`     | Yes            | **No**         | No           |
| `device_token` | Yes            | No             | **Yes**      |

### 7.3. RegisterDeviceToken (Client → Server, type 5)

Registers a routing key with the server for a given application bundle.

| Key                    | Type   | Description                                |
|------------------------|--------|--------------------------------------------|
| `deviceTokenChecksum`  | Data   | The 32-byte `routing_key` (= SHA-256 of K) |
| `appBundleId`          | String | The application's bundle identifier        |

The client MUST wait for an acknowledgment before storing the token locally. If no ack is received within **5 seconds**, the registration is considered failed.

### 7.4. DeviceTokenRegisterAck (Server → Client, type 5)

| Key        | Type   | Description                        |
|------------|--------|------------------------------------|
| `bundleId` | String | The bundle ID that was registered  |

### 7.5. SendFeedback (Client → Server, type 6)

Reports that a routing key is no longer valid (e.g., app uninstalled, user opted out).

| Key             | Type    | Description                          |
|-----------------|---------|--------------------------------------|
| `routing_token` | Data    | The 32-byte routing key to invalidate|
| `type`          | Integer | Feedback type (currently always `0`) |
| `reason`        | String  | Human-readable reason string         |

---

## 8. Connection Lifecycle

### 8.1. Disconnect Messages

**ServerDisconnect** (Server → Client, type 4): The server is shutting down or evicting the client. The client should tear down the TLS session and reconnect with backoff.

**ClientDisconnect** (Client → Server, type 4): The client is intentionally disconnecting. No additional fields.

### 8.2. Reconnection Strategy

Clients MUST implement **exponential backoff**:

```
backoff = 1 second (initial)

loop:
    result = connect_and_authenticate()
    if result == success:
        while handle_message() == success:
            backoff = 1    // reset on healthy traffic
        // message handling returned error
    
    disconnect()
    sleep(backoff)
    backoff = min(backoff * 2, MAX_BACKOFF)   // MAX_BACKOFF = 256 seconds recommended
```

Additionally, clients SHOULD detect **rapid disconnection loops** (3+ disconnections within 10 seconds) and disable themselves to prevent resource exhaustion and server abuse.

### 8.3. Network Awareness

Clients SHOULD monitor network reachability and:
- Attempt connection only when the network is reachable without requiring user interaction
- Re-trigger the connection loop when connectivity is restored
- Guard against multiple concurrent connection loops (e.g., one from initial startup, another from a reachability callback)

---

## 9. End-to-End Encryption

### 9.1. Key Derivation

Both the sending service and the receiving client independently derive the same encryption key from the shared secret `K`:

```
salt = UTF8(server_address) + "Hello from the Skyglow Notifications developers!"

e2ee_key = HKDF-SHA256(
    key_material  = K,                // 16 bytes
    salt          = salt,
    info          = <empty>,
    output_length = 32
)
```

The sender extracts `K` from the device token (bytes 16–31) and the server address from bytes 0–15 (trimming trailing zero bytes).

### 9.2. Encryption (Sender Side)

```
iv = SecureRandom(12)    // 12-byte nonce

ciphertext, tag = AES-256-GCM-Encrypt(
    key       = e2ee_key,
    iv        = iv,
    plaintext = serialize(payload),   // JSON or binary plist
    aad       = <none>
)

// Send to server:
//   ciphertext_with_tag = ciphertext || tag    (tag is 16 bytes)
//   iv                  = iv
//   data_type           = "json" or "plist"
```

### 9.3. Decryption (Client Side)

```
// ciphertext_with_tag has the 16-byte GCM auth tag appended

ciphertext = ciphertext_with_tag[0 .. len-16]
tag        = ciphertext_with_tag[len-16 .. len]

plaintext = AES-256-GCM-Decrypt(
    key  = e2ee_key,       // looked up locally by routing_key
    iv   = iv,             // from the message
    ciphertext = ciphertext,
    tag  = tag,
    aad  = <none>
)
```

If decryption or tag verification fails, the client acknowledges with status code `1`.

---

## 10. Server Infrastructure

### 10.1. Components

| Component   | Default Port | Protocol | Purpose                              |
|-------------|-------------|----------|--------------------------------------|
| TCP Server  | 7373        | TLS      | Persistent client connections        |
| HTTP Server | 7878        | HTTP(S)  | Registration API, push submission    |
| PostgreSQL  | 5432        | —        | Server-side storage                  |

### 10.2. Server Cryptographic Material

The server requires an RSA-4096 keypair:

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout server_private_key.pem \
    -out server_public_key.pem \
    -days 7300 -nodes
```

- `server_public_key.pem` is distributed to clients during registration (used for TLS certificate pinning)
- `server_private_key.pem` is used by the server for TLS and for encrypting login challenges with the client's public key

### 10.3. DNS Configuration

Create a TXT record:

```
_sgn.sgn.example.com  IN  TXT  "tcp_addr=<IP> tcp_port=<TCP_PORT> http_addr=<HTTP_URL>"
```

- `<IP>` — the server's public IPv4 address
- `<TCP_PORT>` — the TLS TCP protocol port (**must not** be the HTTP port)
- `<HTTP_URL>` — the base URL of the HTTP API

---

## 11. Security Considerations

1. **TLS with certificate pinning** prevents man-in-the-middle attacks. The client trusts only the specific server certificate obtained during registration.

2. **RSA challenge-response authentication** ensures mutual verification. The server proves knowledge of the client's public key; the client proves possession of the private key.

3. **Timestamp validation** on challenges prevents replay attacks (5-minute tolerance window).

4. **End-to-end encryption** ensures the server operator cannot read notification payloads. The server only sees opaque routing keys and ciphertext.

5. **Routing key is a one-way hash** of the secret `K`. The server never learns `K` and cannot derive the E2EE key.

6. **Device token structure** embeds the server address, enabling clients to route tokens to the correct server in a multi-server (federated) deployment.

7. **SIGPIPE handling** — clients MUST ignore SIGPIPE to prevent process termination when the server drops the connection unexpectedly.

---

## 12. Implementation Checklist

For implementors targeting a new platform:

- [ ] Binary plist serializer/deserializer (Apple `bplist00` format)
- [ ] TLS 1.0+ client with certificate pinning
- [ ] RSA-OAEP private key decryption (for login challenge)
- [ ] SHA-256 (for routing key derivation)
- [ ] HKDF-SHA256 (for E2EE key derivation)
- [ ] AES-256-GCM decryption (for encrypted notifications)
- [ ] DNS TXT record query
- [ ] Exponential backoff with jitter for reconnection
- [ ] Network reachability monitoring
- [ ] Persistent local storage (for tokens, E2EE keys, and DNS cache)
- [ ] Cryptographically secure random number generator (for K)

---

## Appendix A: Wire Examples

### A.1. LoginRequest

```
Plist dictionary:
{
    "$type":   0,
    "address": "user@skyglow.es",
    "version": "1.0.0",
    "lang":    "en"
}
```

### A.2. LoginChallenge

```
{
    "$type":    1,
    "challenge": <458 bytes: RSA-OAEP encrypted blob>
}
```

Decrypted challenge plaintext (UTF-8):
```
user@skyglow.es,a1b2c3d4e5f6,1708185600.000000
```

### A.3. LoginChallengeResponse

```
{
    "$type":     1,
    "nonce":     "a1b2c3d4e5f6",
    "timestamp": "1708185600.000000"
}
```

### A.4. ReceiveNotification (Encrypted)

```
{
    "$type":        2,
    "routing_key":  <32 bytes>,
    "message_id":   "550e8400-e29b-41d4-a716-446655440000",
    "is_encrypted": true,
    "data_type":    "json",
    "ciphertext":   <N+16 bytes: AES-GCM ciphertext || 16-byte auth tag>,
    "iv":           <12 bytes>
}
```

### A.5. ReceiveNotification (Unencrypted)

```
{
    "$type":        2,
    "routing_key":  <32 bytes>,
    "message_id":   "661f9500-f30c-52e5-b827-557766551111",
    "is_encrypted": false,
    "data": {
        "aps": {
            "alert": "You have a new message",
            "badge": 3,
            "sound": "default"
        }
    }
}
```

### A.6. AckNotification

```
{
    "$type":        3,
    "notification": "550e8400-e29b-41d4-a716-446655440000",
    "status":       0
}
```

### A.7. RegisterDeviceToken

```
{
    "$type":               5,
    "deviceTokenChecksum": <32 bytes: SHA-256(K)>,
    "appBundleId":         "com.example.myapp"
}
```

### A.8. SendFeedback

```
{
    "$type":         6,
    "routing_token": <32 bytes>,
    "type":          0,
    "reason":        "App uninstalled"
}
```

---

## Appendix B: Device Token Binary Layout

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
4. Derive `e2ee_key` using HKDF-SHA256 (see Section 9.1)
5. Derive `routing_key = SHA-256(K)` to include when submitting notifications via the HTTP API