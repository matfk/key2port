# Key2port

**Important**: Key2port is not yet ready for use!

Key2port is a Single Packet Authorization (SPA) tool designed to secure services by keeping them invisible to the public internet. Unlike traditional firewalls that leave ports open, Key2port keeps them closed and only "unlocks" access after receiving a single signed (ed25519) UDP packet.

## Prerequisites

Before installing, ensure you have the following dependencies:

- `gcc` and `make`
- `libsodium`
- `libpcap`
- `libnftables`
- `sqlite3`

On Debian/Ubuntu, you can install them via:
```bash
sudo apt update
sudo apt install build-essential libsodium-dev libpcap-dev libnftables-dev libsqlite3-dev
```

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/matfk/key2port.git
   cd key2port
   ```

2. **Install**:
   ```bash
   sudo scripts/install.sh
   ```
### Server Usage
Run server with sudo or add it to your init system.
```bash
sudo ./k2p-server
```

### Client Usage
To unlock a port (e.g., port 22 for SSH) from a remote machine:

```bash
./k2p-client <user>@<server_ip> -p 22 --ttl 120
```

- `<user>`: The identifier registered in the server's database.
- `<server_ip>`: The IP address of your protected server.
- `-p`: The port you want to open.
- `--ttl`: How long the port should remain open in seconds (default is 120).

After running the client, you have the `ttl` window to connect (e.g., `ssh user@server_ip`). Once the connection is established, the port can safely "close" behind you while your active session remains established.

## Configuration

Configuration files are located in `/etc/k2p/` after installation. You can manage authorized users and their public keys in the `/etc/k2p/keys` directory.

To add a new user, copy their public key into it's own file under `/etc/k2p/keys` and rename the file to the desired username.  
