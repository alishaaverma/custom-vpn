# Custom Python Overlay VPN

A terminal-only, encrypted TCP overlay for giving trusted users access to selected services on another machine. It is built with the Python standard library and runs on Windows or Ubuntu.

The central server authenticates clients, assigns each client a logical private IP, and relays only the TCP ports that the service owner has explicitly allowed.

> This is not a full operating-system VPN. It does not create a TUN/TAP adapter, route all traffic, or make logical IPs directly reachable from other applications. Instead, it creates local TCP forwards such as `127.0.0.1:18080` that securely reach a published remote service.

## What it does

Suppose an owner has a web app listening only on `127.0.0.1:8080`. A user can reach it without exposing that app to the LAN or Internet:

```text
User browser
    |
127.0.0.1:18080
    |
User client ── encrypted TLS-PSK connections ── Overlay server ── Owner client ── 127.0.0.1:8080
```

| Peer | Logical IP | Role |
| --- | --- | --- |
| `owner` | `10.77.0.14` | Publishes local port `8080` |
| `user` | `10.77.0.15` | Forwards local `18080` to `10.77.0.14:8080` |

The user opens `http://127.0.0.1:18080`; the request arrives at the owner's `127.0.0.1:8080`.

## Features and limits

- TLS 1.2 PSK encryption for every client-to-server connection.
- A separate 256-bit PSK for every identity, plus HMAC challenge-response authentication.
- Server-enforced allow-list of published destination ports.
- Automatic control-session reconnection.
- TCP only: no UDP, ICMP, DNS/subnet routing, or full-device traffic tunnel.
- The relay server necessarily sees client source IPs and carries relayed traffic.

## Requirements

- Python **3.13+**
- A Python/OpenSSL build where `ssl.HAS_PSK` is `True`
- Network reachability from clients to the server on TCP `9443` (or your chosen port)
- No pip packages

From the project directory, verify the runtime:

```bash
python main.py check
```

It should end with `Runtime OK`. If `tls_psk` is `false`, use a compatible Python/OpenSSL build; this project deliberately has no insecure fallback.

## Quick start

The following uses the included `owner` and `user` example.

### 1. Start the server

Choose a host reachable by both clients. For same-LAN use, clients can use its LAN address (for example `192.168.1.182`). For off-LAN access, the host needs a public/reachable network path and TCP `9443` forwarded through any router/firewall. This project cannot bypass CGNAT.

```bash
python main.py server --config config/server.example.json
```

Optional helpers:

```bash
bash scripts/setup_ubuntu.sh 9443
```

```powershell
.\scripts\setup_windows.ps1 -Port 9443
```

The Windows helper also creates an inbound firewall rule.

### 2. Create private credentials

```bash
cp credentials/users.example.json credentials/users.json
python main.py gen-psk
```

PowerShell equivalent:

```powershell
Copy-Item credentials\users.example.json credentials\users.json
python main.py gen-psk
```

Run `gen-psk` once for `owner` and once for `user`. Put the two different 64-character hexadecimal values into the matching records in `credentials/users.json`.

Do not commit this file. It is already Git-ignored.

### 3. Configure and start both clients

On the owner machine:

```bash
cp config/client.owner.example.json config/client.owner.json
python main.py client --config config/client.owner.json
```

On the user machine:

```bash
cp config/client.user.example.json config/client.user.json
python main.py client --config config/client.user.json
```

In both configs, replace `server_host` with the server address and set `psk_hex` to the matching credential value. Start the owner client before the user client and keep both running.

### 4. Access the service

On the user machine:

```bash
curl http://127.0.0.1:18080
```

For a web app, open `http://127.0.0.1:18080` in a browser.

## Configuration reference

### Server config

`config/server.example.json` controls the relay server:

| Field | Meaning |
| --- | --- |
| `host` | Bind address; `0.0.0.0` accepts network connections. |
| `port` | Client TCP port; default `9443`. |
| `credentials_file` | Private server-side users file. |
| `pending_timeout_seconds` | Time to wait for a target client to accept a relay. |
| `log_level` / `log_file` | Logging controls. |

### Credentials

`credentials/users.json` is the server's source of truth:

```json
{
  "identity": "owner",
  "psk_hex": "64_HEX_CHARACTER_SECRET",
  "virtual_ip": "10.77.0.14",
  "allowed_ports": [8080],
  "enabled": true
}
```

- `identity` and `virtual_ip` must each be unique.
- Virtual IPs must be private addresses.
- `allowed_ports` is enforced by the server; client settings cannot bypass it.
- Set `enabled` to `false` to disable an identity.

### Client config

Every client needs matching `server_host`, `server_port`, `identity`, and `psk_hex`. `heartbeat_seconds` controls keepalives; `reconnect_seconds` controls retry delay.

`published_services` maps an allowed virtual port to a service local to that client:

```json
{
  "virtual_port": 8080,
  "local_host": "127.0.0.1",
  "local_port": 8080
}
```

`virtual_port` must appear in that user's server-side `allowed_ports`. Keep `local_host` on `127.0.0.1` unless the service should also be network-accessible.

`forwards` creates a local listener that reaches a target logical IP:

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_virtual_ip": "10.77.0.14",
  "target_port": 8080
}
```

Keep `listen_host` as `127.0.0.1` to prevent other devices from using the forward. `0.0.0.0` exposes it on the network.

## Add a user or service

1. Generate a new PSK.
2. Add an enabled credential record with a unique identity and virtual IP.
3. Add required published ports to `allowed_ports`.
4. Create the client config with the matching identity and PSK.
5. Add `published_services` for hosted services or `forwards` for consumed ones.
6. Restart the server after credentials changes, then restart affected clients.

Many clients may target the same service. Only the peer-assigned virtual IPs must be unique.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Python version or `HAS_PSK` error | Run `python main.py check`; use Python 3.13+ with TLS-PSK support. |
| Client cannot connect | Verify server address, port, server process, firewall, and router forwarding. |
| Authentication fails | Check identity and PSK against the enabled credential record. |
| Target is offline | Start the target peer client and wait for it to register. |
| Port is not allowed | Add the port to the target user's `allowed_ports` and restart the server. |
| Forward fails | Confirm the target service is running and listed in `published_services`. |
| Address already in use | Change `listen_port` or stop the process using it. |

Example configs write logs under `logs/`. Create it before using file logging:

```bash
mkdir -p logs
```

## Security checklist

- Use a unique PSK per user; rotate it if it may be exposed.
- Never commit or share `credentials/users.json` or real client configs.
- Assign a unique private virtual IP to every identity.
- Keep `allowed_ports` narrow.
- Bind services and forwards to `127.0.0.1` unless wider access is deliberate.
- Restrict the server listening port with host and network firewall rules.

## Commands

```bash
python main.py check
python main.py gen-psk
python main.py server --config config/server.example.json
python main.py client --config config/client.owner.json
```

## Project layout

```text
main.py              CLI entry point
server/              Server, session registry, and relay coordination
client/              Client agent, published services, and local forwards
network/             TLS-PSK, authentication, framing, and relay code
credentials/         Server-side identity and access policy
config/              Server and client templates
scripts/             Windows and Ubuntu setup helpers
```
