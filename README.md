# Custom Python Overlay VPN / Private Tunnel

Terminal-only, Python-standard-library secure overlay for project access on Windows and Ubuntu.

## Important scope

This is an application-layer encrypted overlay tunnel, not a kernel-level TUN/TAP VPN. It does not create a real OS network interface on Windows. That is intentional: Windows 11 needs a VPN plug-in/virtual adapter/driver for a true transparent L3 VPN, which conflicts with the "Python only, no external component" requirement.

The overlay gives each authenticated user a unique logical virtual IP. A service may be published under one logical virtual IP and another user can target that logical IP through the CLI agent.

Example:
- owner physical/LAN IP: `192.168.1.182`
- user physical/LAN IP: `192.168.1.132`
- owner logical VPN IP: `10.77.0.14`
- user logical VPN IP: `10.77.0.15`
- owner publishes project port `8080` under `10.77.0.14:8080`
- user forwards local `127.0.0.1:18080` to virtual `10.77.0.14:8080`

The owner and user must NOT both be assigned `10.77.0.14`; duplicate peer IPs are ambiguous. They can both use the same *service target* `10.77.0.14`.

## Requirements

- Python 3.13+
- No pip packages
- Python/OpenSSL build must report `ssl.HAS_PSK == True`

Check:

```bash
python main.py check
```

Generate one PSK per user:

```bash
python main.py gen-psk
```

## Quick start

1. Copy `credentials/users.example.json` to `credentials/users.json`.
2. Generate two PSKs and put one in `owner` and one in `user`.
3. Copy `config/client.owner.example.json` to `config/client.owner.json` and place the owner PSK in it.
4. Copy `config/client.user.example.json` to `config/client.user.json` and place the user PSK in it.
5. Put the real server address in both client config files.
6. Run the server:

```bash
python main.py server --config config/server.example.json
```

7. On the machine that owns the application, run:

```bash
python main.py client --config config/client.owner.json
```

8. On the user's machine, run:

```bash
python main.py client --config config/client.user.json
```

9. User can access the owner's published service through the local forward:

```bash
curl http://127.0.0.1:18080
```

Or open `http://127.0.0.1:18080` in a browser if the published application is a web application.

## Security model

- TLS-PSK encrypts transport.
- Every user receives a separate 256-bit PSK.
- Application-level HMAC challenge-response prevents one valid TLS user from claiming another identity.
- Server-side credentials define the logical virtual IP and allowed published ports.
- The peer's physical/LAN IP is not used as the application-layer identity.
- The central server can still see the physical/public source address because that is required to carry the underlying network connection.

## Router note

For same-LAN testing, clients can connect directly to the server's LAN IP.
For Internet access, the server needs a reachable public IP/network path and TCP `9443` forwarded to it. This project cannot bypass CGNAT or the absence of a network path.
