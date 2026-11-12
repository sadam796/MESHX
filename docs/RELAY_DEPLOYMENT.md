# MESHX public relay node (experimental)

This repository now contains a self-hostable libp2p circuit-relay v2 server binary and a Docker Compose recipe.

## What it provides

- A public TCP listener (default port 4001).
- libp2p Noise/Yamux transport and circuit-relay v2 reservations/forwarding. The HOP protocol is explicitly enabled for this dedicated relay service.
- A persistent Ed25519 relay identity file, so the relay Peer ID remains stable across restarts.
- A non-root container process and a persistent Docker volume for the relay identity.

The server now exposes an experimental durable mailbox protocol at /meshx/mailbox/1 in addition to circuit-relay v2. An authenticated sender can store an already-encrypted envelope; the recipient can fetch envelopes addressed to its authenticated Peer ID and acknowledge each only after durable local save. Fetch does not delete messages. The disk-backed queue survives server restarts and retains replay markers until message expiry.

The Android native transport now includes an experimental mailbox client: it sends Store requests to configured relays, polls Fetch periodically, and sends recipient Acknowledge requests after the app's encrypted local-save flow. This client has not yet been verified against a running public relay or on two physical Android devices. Do not describe public offline delivery as verified.

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
- `MESHX_MAILBOX_DIR`: durable mailbox directory. Default `./data/mailbox`.
- `MESHX_MAILBOX_MAX_ENTRIES`: global pending-message limit. Default `1000`.
- `MESHX_MAILBOX_MAX_BYTES`: global pending-ciphertext limit. Default `536870912` (512 MiB).

## Release and security limitations

- This server has not been deployed to a public host from this repository.
- Android now has experimental mailbox client wiring, but a running Android-to-server exchange and real-world cross-network message delivery have not yet been verified.
- Circuit relay v2 forwards live peer traffic; it does not store messages for offline recipients.
- Mailbox requests are authenticated against the libp2p Peer ID established by the Noise connection: store requires sender_id to match the connected peer; fetch is scoped to that peer; acknowledgement can delete only a message addressed to that peer.
- The mailbox stores encrypted message envelopes, but routing metadata is visible to the relay and is not encrypted at rest. The mailbox directory is created with mode 0700 and files with mode 0600 on Unix-like hosts.
- The mailbox currently has global capacity limits only. Per-peer quotas, rate limits, monitoring, DDoS protection, abuse reporting, operator controls, and service-level guarantees are not provided.
- Run only as an experimental test node until those controls and end-to-end Android integration are completed.
