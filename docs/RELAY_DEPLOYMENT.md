# MESHX public relay node (experimental)

This repository now contains a self-hostable libp2p circuit-relay v2 server binary and a Docker Compose recipe.

## What it provides

- A public TCP listener (default port 4001).
- libp2p Noise/Yamux transport and circuit-relay v2 reservations/forwarding. The HOP protocol is explicitly enabled for this dedicated relay service.
- A persistent Ed25519 relay identity file, so the relay Peer ID remains stable across restarts.
- A non-root container process and a persistent Docker volume for the relay identity.

This is a reachable-peer relay, not an offline message mailbox. A recipient must still be reachable through the relay for circuit-relay forwarding. The separate disk-backed ciphertext mailbox prototype is not exposed as a network service and is not integrated with Android.

## Deploy on a Linux VPS

Requirements: a Linux VPS with Docker Engine and the Docker Compose plugin, a public IPv4 address, and permission to open inbound TCP port 4001.

From this directory:

```sh
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml logs -f
```

Allow inbound TCP port 4001 in both the VPS firewall and hosting-provider firewall. The relay prints its Peer ID and full listening multiaddress at startup. Record the complete `/ip4/<PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>` address; clients must be configured with that exact address.

The Compose volume `meshx-relay-data` preserves the private relay identity. Back it up securely. Do not publish or share `relay-identity.key`. Losing the key changes the relay Peer ID; restoring the volume preserves it.

## Environment

- `MESHX_RELAY_LISTEN`: libp2p multiaddress to listen on. Default `/ip4/0.0.0.0/tcp/4001`.
- `MESHX_RELAY_KEY_FILE`: private identity file path. Default `./data/relay-identity.key`.
- `MESHX_RELAY_PUBLIC_ADDRESS`: optional public-facing multiaddress without the terminal `/p2p/<PEER_ID>`, for example `/ip4/<PUBLIC_IP>/tcp/4001`. Set this in the VPS environment so the relay can advertise the address in reservation vouchers. If omitted, users must enter the VPS address directly in the app.

## Release and security limitations

- This server has not been deployed to a public host from this repository.
- The Android app does not yet connect to this relay; no real-world cross-network message delivery is claimed.
- Circuit relay v2 forwards live peer traffic; it does not store messages for offline recipients.
- The experimental durable mailbox queue is a local library abstraction, not a remotely authenticated mailbox API.
- No production quotas, monitoring, DDoS protection, abuse reporting, operator authentication, or service-level guarantees are provided.
- Run only as an experimental test node until those controls and end-to-end Android integration are completed.
