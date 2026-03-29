# Net Path Probe

Net Path Probe is a **unified listener + tester** for broad, authorized server-to-server connectivity validation. It is designed for operators who need a practical answer to questions like:

- “Can my source server really reach the destination over this class of transport?”
- “Which protocol families are open, blocked, or only partially testable?”
- “Which checks are exact, and which are approximations due to kernel/library constraints?”

> **Safety and scope**
>
> This project is intended for **authorized diagnostics between systems you control**. The “tunneling” notes in this README are intentionally **high-level and defensive**. They are meant to help operators choose legitimate transport designs, not to provide bypass or covert-channel instructions.

## What the project does

- Runs a **background listener** on the destination host.
- Runs a **tester** on the source host.
- Prints `OK`, `DENY`, or `WARN` for each protocol entry in the matrix.
- Uses **dedicated high test ports** by default so it does not collide with production services.
- Distinguishes between:
  - **exact-ish practical tests** (for example, HTTP request/response, SSH banner, Redis PING/PONG)
  - **minimal protocol probes** (for example, a small banner or request/response probe)
  - **fallback/simulated checks** where the exact protocol requires extra kernel or user-space support

## Quick start

### Destination host

```bash
python3 net_path_probe.py --listen
```

### Source host

```bash
python3 net_path_probe.py --test
```

Or launch the file without flags and use the interactive menu.

## Output semantics

- `OK`: the configured check completed successfully.
- `DENY`: the path, handshake, or response failed.
- `WARN`: the protocol is listed in the matrix, but the current portable implementation cannot validate it exactly on this host without additional kernel support, privileges, or libraries.

## Architecture

### Runtime architecture

```text
+--------------------+                         +-------------------------+
| Source server      |                         | Destination server      |
|                    |                         |                         |
| tester mode        |  TCP/UDP/TLS/HTTP/etc  | listener mode           |
| - protocol matrix  | ---------------------> | - protocol handlers     |
| - result engine    | <--------------------- | - daemonized listener   |
| - path diagnostics |       responses        | - dedicated test ports  |
+--------------------+                         +-------------------------+
```

### Internal model

The current implementation is intentionally simple:

1. **One Python entry point** (`net_path_probe.py`)
2. **One listener daemon** that binds multiple test ports
3. **One tester engine** that runs the protocol matrix
4. **Protocol handlers** grouped as:
   - banner-style TCP handlers
   - request/response TCP handlers
   - UDP token responders
   - TLS token responders
   - HTTP/HTTPS handlers
   - limited/fallback entries for protocols that need more than the standard library

### Why dedicated high ports?

The listener uses dedicated high, non-standard test ports so it does not break or hijack a real production daemon already bound to the conventional port. That makes the tool safer to run on existing hosts.

## Development guide

### Add a new protocol entry

1. Add the listener behavior:
   - TCP banner handler, or
   - TCP request/response handler, or
   - UDP responder, or
   - TLS responder, or
   - HTTP route.
2. Add the tester probe.
3. Add the protocol row to the README tables.
4. Mark it as one of:
   - exact practical probe
   - minimal probe
   - fallback/simulated
5. Document the official source.

### When to move from fallback to exact support

Add exact support only when all of the following are true:

- the protocol is important to your environment,
- the required libraries or kernel features are acceptable,
- you can test it safely in CI or a lab,
- and the README clearly explains the new trust/privilege assumptions.

### Suggested future work

- optional JSON output for CI pipelines
- exact QUIC/HTTP/3 support through a maintained library
- exact SCTP support on supported kernels
- optional raw-socket mode for GRE/IPIP/ESP/AH on lab hosts with explicit root access
- container-based integration tests

## Protocol matrix

The table below explains **what this project tests now**, plus a **high-level legitimate encapsulation/tunneling note** for each protocol family.

| Protocol | Current meaning in this project | Legitimate encapsulation / tunneling note | Primary reference |
|---|---|---|---|

| ICMP | Network diagnostics: Reachability/path check via echo-style probing. Not a data tunnel. | Do not tunnel ICMP itself for application traffic. Use a proper VPN/overlay for production paths. | [`RFC792`](https://www.rfc-editor.org/rfc/rfc792.html) |
| TCP | Transport: Generic reliable byte-stream reachability test. | Carry applications over routed IP, private links, or a VPN/overlay. Avoid ad-hoc covert TCP tunneling. | [`RFC9293`](https://www.rfc-editor.org/rfc/rfc9293.html) |
| UDP | Transport: Generic datagram reachability test. | Use a routed path or a VPN/overlay. Be explicit about MTU, NAT, and keepalives. | [`RFC768`](https://www.rfc-editor.org/rfc/rfc768.html) |
| SCTP | Transport: Optional test; exact support depends on kernel/socket availability. | Only use when both endpoints and the path explicitly support SCTP; otherwise prefer TCP/UDP-based overlays. | [`RFC9260`](https://www.rfc-editor.org/rfc/rfc9260.html) |
| QUIC | Transport + security: This project uses a fallback/approximation unless a full QUIC stack is added. | If you need QUIC in production, use an implementation that actually speaks QUIC; do not treat a UDP echo as an exact QUIC test. | [`RFC9000`](https://www.rfc-editor.org/rfc/rfc9000.html) |
| GRE | IP tunnel: Listed in the matrix, but exact validation needs raw sockets and root. | Use only as an intentional site-to-site overlay between authorized peers; pair with IPsec if confidentiality is needed. | [`RFC2784`](https://www.rfc-editor.org/rfc/rfc2784.html) |
| IPIP | IP tunnel: Listed in the matrix; exact validation needs raw IP handling. | Use only as an intentional point-to-point IP overlay between authorized peers. | [`RFC2003`](https://www.rfc-editor.org/rfc/rfc2003.html) |
| IPsec ESP | Security / tunnel: Exact validation is outside portable user-space mode. | Use ESP for confidentiality/integrity as part of a real IPsec deployment. | [`RFC4303`](https://www.rfc-editor.org/rfc/rfc4303.html) |
| IPsec AH | Security / tunnel: Exact validation is outside portable user-space mode. | Use AH only when you explicitly need header authentication semantics and your stack supports it. | [`RFC4302`](https://www.rfc-editor.org/rfc/rfc4302.html) |
| L2TP | Tunnel: UDP-based listener/probe in the test matrix. | For production, deploy as a real L2TP/L2TPv3 design and combine with IPsec when confidentiality is needed. | [`RFC2661`](https://www.rfc-editor.org/rfc/rfc2661.html) |
| WireGuard | VPN: UDP-based listener/probe in the test matrix. | Preferred modern overlay for many administrative use cases. Use only between authorized peers with managed keys. | [`WGPROTO`](https://www.wireguard.com/protocol/), [`WGQUICK`](https://www.wireguard.com/quickstart/) |
| OpenVPN/UDP | VPN: UDP-based listener/probe in the test matrix. | Use only as a deliberate VPN between authorized peers. Prefer the official client/server workflow and certificates/keys. | [`OVPNMAN`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/) |
| OpenVPN/TCP | VPN: TCP-based listener/probe in the test matrix. | Reserve TCP mode for cases where UDP is not viable; avoid unnecessary TCP-over-TCP layering. | [`OVPNMAN`](https://openvpn.net/community-resources/reference-manual-for-openvpn-2-6/) |
| VXLAN | Overlay: UDP-based listener/probe in the test matrix. | Use for L2 overlays between trusted segments and controlled VTEPs. | [`RFC7348`](https://www.rfc-editor.org/rfc/rfc7348.html) |
| Geneve | Overlay: UDP-based listener/probe in the test matrix. | Use for programmable virtualized overlays between trusted endpoints. | [`RFC8926`](https://www.rfc-editor.org/rfc/rfc8926.html) |
| SSH | Secure remote shell: Banner/probe style verification. | Expose only on private networks, via bastions, or through a VPN/overlay; avoid broad Internet exposure. | [`RFC4253`](https://www.rfc-editor.org/rfc/rfc4253.html) |
| RDP | Remote desktop: Connectivity/probe style verification. | Keep on private networks or behind a secure remote access layer; do not publish directly unless strongly controlled. | [`RDP`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c) |
| HTTP | Web application: HTTP request/response verification. | Tunnel at the network layer (VPN/overlay) or through a reverse proxy/load balancer rather than inventing custom tunnels. | [`RFC9110`](https://www.rfc-editor.org/rfc/rfc9110.html) |
| HTTPS | Web application: HTTPS request/response verification. | Prefer normal TLS termination and private routing or VPN overlays instead of protocol abuse. | [`RFC9110`](https://www.rfc-editor.org/rfc/rfc9110.html) |
| HTTP/2 | Web application: Current project uses a simulation/fallback unless full HTTP/2 framing is implemented. | If HTTP/2 is required, use a real HTTP/2 stack or proxy that negotiates and serves it correctly. | [`RFC9113`](https://www.rfc-editor.org/rfc/rfc9113.html) |
| HTTP/3 | Web application: Current project uses a simulation/fallback unless full QUIC/HTTP/3 support is added. | Use an actual QUIC/HTTP/3 implementation for production; do not treat UDP reachability as full HTTP/3. | [`RFC9114`](https://www.rfc-editor.org/rfc/rfc9114.html), [`RFC9000`](https://www.rfc-editor.org/rfc/rfc9000.html) |
| WebSocket | Web application: HTTP Upgrade handshake verification. | Carry through normal HTTPS/reverse-proxy paths or inside your VPN/overlay. | [`RFC6455`](https://www.rfc-editor.org/rfc/rfc6455.html) |
| gRPC | RPC over HTTP/2: Current project uses a simulation/fallback unless a full gRPC stack is added. | Deploy with a real gRPC/HTTP/2 stack and protect it with TLS and/or private routing. | [`GRPC`](https://grpc.io/docs/what-is-grpc/core-concepts/), [`RFC9113`](https://www.rfc-editor.org/rfc/rfc9113.html) |
| DNS | Name resolution: Minimal DNS-style reachability/probe. | For confidentiality, prefer DoT or DoH; for internal transport, prefer a private routed network or VPN. | [`RFC1035`](https://www.rfc-editor.org/rfc/rfc1035.html) |
| DoT | Encrypted DNS: TLS-based verification. | Use a real resolver speaking DoT; keep certificate management and client policy explicit. | [`RFC7858`](https://www.rfc-editor.org/rfc/rfc7858.html) |
| DoH | Encrypted DNS: HTTPS `/dns-query` style verification. | Use a real DoH endpoint over HTTPS; apply the same TLS and access controls as web services. | [`RFC8484`](https://www.rfc-editor.org/rfc/rfc8484.html) |
| NTP | Time sync: Minimal NTP-style UDP reachability/probe. | Keep NTP on controlled network paths or inside your private overlay when possible. | [`RFC5905`](https://www.rfc-editor.org/rfc/rfc5905.html) |
| FTP | File transfer: Banner/probe style verification. | If you need encrypted transport, use FTPS, SFTP, or a VPN/overlay instead of plain FTP over untrusted networks. | [`RFC959`](https://www.rfc-editor.org/rfc/rfc959.html) |
| FTPS | File transfer over TLS: TLS-based verification. | Use explicit policy and certificates; prefer modern TLS configuration. | [`RFC4217`](https://www.rfc-editor.org/rfc/rfc4217.html) |
| SFTP | File transfer over SSH: Mapped to the SSH transport because SFTP runs inside SSH. | Prefer SFTP/SSH over plain FTP when crossing untrusted networks, and keep it behind bastions/VPN where possible. | [`SFTPDRAFT`](https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-13), [`RFC4253`](https://www.rfc-editor.org/rfc/rfc4253.html) |
| TFTP | Simple file transfer: Minimal UDP-style probe. | Use only on tightly controlled networks; avoid using it across untrusted paths. | [`RFC1350`](https://www.rfc-editor.org/rfc/rfc1350.html) |
| Rsync | File sync: Banner/probe style verification. | Prefer rsync over SSH or another authenticated private path instead of exposing a daemon broadly. | [`RSYNC`](https://download.samba.org/pub/rsync/rsync.1) |
| SMTP | Mail transport: Banner/probe style verification. | Protect with TLS and proper mail security controls; do not invent mail-over-covert-tunnel patterns. | [`RFC5321`](https://www.rfc-editor.org/rfc/rfc5321.html) |
| IMAP | Mail access: Banner/probe style verification. | Keep on private or authenticated paths and prefer TLS-protected access. | [`RFC9051`](https://www.rfc-editor.org/rfc/rfc9051.html) |
| POP3 | Mail access: Banner/probe style verification. | Keep on private or authenticated paths and prefer TLS-protected access. | [`RFC1939`](https://www.rfc-editor.org/rfc/rfc1939.html) |
| MQTT | Messaging / IoT: Minimal CONNECT/CONNACK style verification. | Protect with TLS, authentication, and network segmentation or a VPN for remote sites. | [`MQTT`](https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html) |
| AMQP | Messaging: Protocol header verification. | Protect with TLS and network segmentation or a VPN between sites. | [`AMQP`](https://docs.oasis-open.org/amqp/core/v1.0/os/amqp-core-overview-v1.0-os.html) |
| STOMP | Messaging: CONNECT/CONNECTED style verification. | Protect with TLS and private routing or a VPN overlay. | [`STOMP`](https://stomp.github.io/stomp-specification-1.2.html) |
| CoAP | Constrained application protocol: Minimal UDP-style probe. | For real deployments, pair with DTLS/OSCORE and keep the path controlled. | [`RFC7252`](https://www.rfc-editor.org/rfc/rfc7252.html) |
| SMB/CIFS | File sharing: Probe style verification. | Keep SMB on private networks or strongly controlled gateways/VPNs; avoid direct Internet exposure. | [`SMB`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4287490c-602c-41c0-a23e-140a1f137832) |
| NFS | File sharing: Probe style verification. | Keep NFS on trusted networks or private overlays only. | [`RFC7530`](https://www.rfc-editor.org/rfc/rfc7530.html) |
| LDAP | Directory access: Probe style verification. | Prefer StartTLS/TLS and private routing; avoid direct exposure. | [`RFC4511`](https://www.rfc-editor.org/rfc/rfc4511.html), [`RFC4513`](https://www.rfc-editor.org/rfc/rfc4513.html) |
| LDAPS | Directory access over TLS: TLS-based verification. | Use only with explicit certificate management and private routing or VPNs. | [`RFC4511`](https://www.rfc-editor.org/rfc/rfc4511.html), [`RFC4513`](https://www.rfc-editor.org/rfc/rfc4513.html) |
| Redis RESP | Database protocol: PING/PONG style verification. | Keep on private networks only or behind a controlled access layer; do not expose broadly. | [`RESP`](https://redis.io/docs/latest/develop/reference/protocol-spec/) |
| MySQL protocol | Database protocol: Handshake-style verification. | Keep database protocols on private network segments or inside a VPN/overlay; terminate TLS where appropriate. | [`MYSQL`](https://dev.mysql.com/doc/dev/mysql-server/9.5.0/PAGE_PROTOCOL.html) |
| PostgreSQL protocol | Database protocol: Startup/message-flow style verification. | Keep database protocols on private network segments or inside a VPN/overlay; terminate TLS where appropriate. | [`PGPROTO`](https://www.postgresql.org/docs/current/protocol.html) |
| SIP | Signaling: Minimal SIP-style verification. | For real deployments, use a SIP-aware design (proxy/SBC/NAT traversal) or a controlled private overlay. | [`RFC3261`](https://www.rfc-editor.org/rfc/rfc3261.html) |
| RTP | Media transport: Minimal RTP-style probe. | Use with RTP/RTCP-aware media paths or a VPN/private transport; be careful with latency and MTU. | [`RFC3550`](https://www.rfc-editor.org/rfc/rfc3550.html) |
| RTSP | Streaming control: OPTIONS/response style verification. | Protect with TLS where applicable and keep media/control on controlled paths. | [`RFC7826`](https://www.rfc-editor.org/rfc/rfc7826.html) |
| SNMP | Network management: Minimal UDP-style probe. | Restrict to management networks or private overlays; prefer SNMPv3 security features. | [`RFC3416`](https://www.rfc-editor.org/rfc/rfc3416.html) |
| Telnet | Legacy remote access: Banner/probe style verification. | Avoid on untrusted networks; prefer SSH or private, segmented legacy zones only. | [`RFC854`](https://www.rfc-editor.org/rfc/rfc854.html) |
| PPTP | Legacy VPN: Probe style verification. | Prefer modern alternatives such as WireGuard, IPsec, or OpenVPN for new deployments. | [`RFC2637`](https://www.rfc-editor.org/rfc/rfc2637.html) |
| VNC | Remote desktop: RFB banner/probe style verification. | Keep on private networks or behind a secure access layer; do not publish directly. | [`RFC6143`](https://www.rfc-editor.org/rfc/rfc6143.html) |
| Syslog | Logging: Minimal syslog-style UDP reachability/probe. | Use private transport, relays, or TLS-capable syslog designs where required by policy. | [`RFC5424`](https://www.rfc-editor.org/rfc/rfc5424.html) |


## Recommended operator interpretation

- Prefer **modern secure overlays** such as **WireGuard**, **IPsec**, or **OpenVPN** when you need confidentiality across untrusted networks.
- Prefer **private routed segments** or **overlay networks** for database, storage, and management protocols.
- Prefer **protocol-aware infrastructure** for SIP/RTP, reverse-proxied web stacks, and production service meshes.
- Treat legacy protocols such as **Telnet**, **PPTP**, and plain **FTP** as compatibility cases, not default choices.

## Reference notes

- RFC links point to the RFC Editor or IETF datatracker.
- Some vendor protocols use official vendor/open-spec references.
- SFTP is referenced with the long-used SSH File Transfer draft because it never became a standalone RFC in the same way many other protocols did.

## License / contribution note

Before opening a pull request, keep changes small, explain whether a probe is exact or simulated, and update both English and Persian READMEs together.
