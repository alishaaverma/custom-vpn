# Custom Python Overlay VPN

A dependency-free Python TCP overlay for two related use cases:

- securely exposing selected TCP services between authenticated peers; and
- providing an optional local SOCKS5 proxy that sends proxied TCP traffic out through the relay server.

It uses Python's standard `ssl` module with a server certificate. Each client is then authenticated with its own 256-bit PSK and an HMAC challenge-response exchange.

> This is **not** a full-device VPN. It does not create a TUN/TAP adapter, change operating-system routes, provide a kill switch, or tunnel UDP, ICMP, or all DNS traffic. Only TCP connections explicitly sent to a configured local forward or the SOCKS5 proxy use the overlay.

## How traffic flows

### Private service forwarding

```text
User application
    |
127.0.0.1:18080 (local forward)
    |
User client -- certificate TLS --> Relay server -- certificate TLS --> Owner client --> 127.0.0.1:8080
```

Logical private IPs are only overlay addresses; they are not operating-system network interfaces.

### Optional SOCKS5 egress

```text
Browser or app configured for SOCKS5
    |
127.0.0.1:1080
    |
User client -- encrypted TLS --> Relay server --> public website
```

For traffic that actually uses this proxy, websites see the relay server's public IP, not the user's public IP. The relay server still sees the user's source IP. Apps that bypass the proxy, UDP traffic, and system traffic are not protected by this project.

## Security model and limits

- TLS 1.2+ encrypts each client-to-server channel. Clients verify the configured server certificate.
- Every enabled identity has a distinct 256-bit PSK. The PSK is used by the application's HMAC challenge-response authentication, not TLS-PSK.
- The server enforces which target overlay ports may be opened.
- SOCKS egress is opt-in per identity through `allow_egress` and is limited to destinations resolving to public IP addresses.
- The SOCKS listener has no username/password authentication. Keep it bound to `127.0.0.1`; do not expose it to a LAN or the Internet.
- The relay server is trusted infrastructure: it carries the decrypted proxied TCP stream after TLS terminates there.

## Requirements

- Python **3.10+**
- OpenSSL command-line utility, once, to create the server certificate
- A relay server reachable by each client on TCP `9443` (or your chosen port)
- No pip packages

Check the installed runtime:

```bash
python main.py check
```

It should finish with `Runtime OK`. `tls_psk: false` in diagnostic output is expected; the project uses certificate TLS.

## Setup

The commands below use the supplied `owner` and `user` examples. Do not use example PSKs in a real deployment.

### 1. Create the server certificate

Run this on the relay server from the project directory:

```bash
mkdir -p certs logs
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 \
  -keyout certs/server.key -out certs/server.crt -subj "/CN=custom-python-vpn"
```

`certs/server.key` must remain on the relay server. Copy only `certs/server.crt` securely to every client and set each client's `tls_ca_file` to the copy's local path. Certificate and key files are Git-ignored.

### 2. Create credentials

On the relay server:

```bash
cp credentials/users.example.json credentials/users.json
python main.py gen-psk
```

Generate one PSK for each identity and replace the corresponding `psk_hex` values in `credentials/users.json`. Every identity and `virtual_ip` must be unique.

### 3. Configure and start the relay server

Set the server host, port, credential store, and certificate paths in `config/server.example.json`, or create a separate private server config:

```json
{
  "host": "0.0.0.0",
  "port": 9443,
  "credentials_file": "credentials/users.json",
  "tls_cert_file": "certs/server.crt",
  "tls_key_file": "certs/server.key"
}
```

Start it:

```bash
python main.py server --config config/server.example.json
```

Allow the selected TCP port through the host firewall and, for Internet clients, the router/cloud firewall. CGNAT cannot be bypassed by this project.

### 4. Configure and start clients

Copy the relevant example config on each machine, set `server_host`, `identity`, the matching `psk_hex`, and `tls_ca_file`, then run it:

```bash
cp config/client.owner.example.json config/client.owner.json
python main.py client --config config/client.owner.json
```

```bash
cp config/client.user.example.json config/client.user.json
python main.py client --config config/client.user.json
```

Start the owner client before a user tries to reach an owner-published service.

### 5. Verify a published service

With the example owner service running on `127.0.0.1:8080`, run on the user machine:

```bash
curl http://127.0.0.1:18080
```

## SOCKS5 egress setup

Enable egress only for identities that need it in `credentials/users.json`:

```json
{
  "identity": "user",
  "allow_egress": true
}
```

Add a localhost SOCKS listener to that client's config:

```json
"socks5": {
  "listen_host": "127.0.0.1",
  "listen_port": 1080
}
```

Restart the server after changing credentials and restart the affected client. Configure the browser or app to use SOCKS5 host `127.0.0.1`, port `1080`.

To test the IP shown to a website after server and client are running:

```bash
curl --proxy socks5h://127.0.0.1:1080 https://api.ipify.org
```

The returned address should be the relay server's public IP. `socks5h` sends the hostname through the proxy so resolution occurs on the relay side.

## Configuration reference

### Server config

| Field | Meaning |
| --- | --- |
| `host`, `port` | Relay bind address and TCP listener port. |
| `credentials_file` | Server-side user and authorization store. |
| `tls_cert_file`, `tls_key_file` | Server certificate and its private key. |
| `pending_timeout_seconds` | Wait time for the target peer to accept a service relay. |
| `log_level`, `log_file` | Logging controls. Create the log directory first. |

### Credential record

```json
{
  "identity": "owner",
  "psk_hex": "64_HEX_CHARACTER_SECRET",
  "virtual_ip": "10.77.0.14",
  "allowed_ports": [8080],
  "allow_egress": false,
  "enabled": true
}
```

- `allowed_ports` controls published-service destinations for that identity.
- `allow_egress` defaults to `false`; set it to `true` only for trusted users who need SOCKS5 Internet access.
- Set `enabled` to `false` to deny a user at their next connection.

### Client config

| Field | Meaning |
| --- | --- |
| `server_host`, `server_port` | Relay address. |
| `identity`, `psk_hex` | Credentials matching an enabled server record. |
| `tls_ca_file` | Path to the trusted relay-server certificate. |
| `published_services` | Local TCP services made available to authorized overlay peers. |
| `forwards` | Local TCP listeners connected to an overlay peer's logical IP and allowed port. |
| `socks5` | Optional local SOCKS5 listener for egress; use `127.0.0.1`. |

`published_services` example:

```json
{
  "virtual_port": 8080,
  "local_host": "127.0.0.1",
  "local_port": 8080
}
```

`forwards` example:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_virtual_ip": "10.77.0.14",
  "target_port": 8080
}
```

### Environment overrides

`main.py` loads `.env` before parsing commands. These environment variables override JSON values: `VPN_SERVER_CONFIG`, `VPN_CLIENT_CONFIG`, `VPN_SERVER_HOST`, `VPN_SERVER_PORT`, `VPN_CREDENTIALS_FILE`, `VPN_TLS_CERT_FILE`, `VPN_TLS_KEY_FILE`, `VPN_CLIENT_SERVER_HOST`, `VPN_CLIENT_SERVER_PORT`, `VPN_CLIENT_IDENTITY`, `VPN_CLIENT_PSK_HEX`, and `VPN_TLS_CA_FILE`.

Use `.env.example` as a template, but replace all placeholder values. Environment values take precedence over JSON config values.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `Runtime OK` does not appear | Use Python 3.10+ and run the command from the project directory. |
| Certificate verification/loading error | Ensure the server has both cert and key, clients have the cert only, and paths are correct. |
| Client cannot connect | Verify relay address, TCP port, server process, firewall, and router/cloud rules. |
| Authentication error | Match `identity` and PSK with an enabled server credential record. |
| Target is offline | Start the target peer client and wait for it to register. |
| SOCKS request fails | Enable `allow_egress`, restart server/client, and use a public TCP destination. |
| Address already in use | Change the local forward/SOCKS port or stop the process using it. |

## Project layout

```text
main.py              CLI entry point
server/              Relay listener, sessions, and authorization
client/              Client agent, local forwards, and SOCKS5 listener
network/             TLS, authentication, framing, and relay code
credentials/         Server-side identity and access policy
config/              Server and client templates
certs/               Local certificate/key files (not committed)
```
