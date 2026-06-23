# ekey UDP for Home Assistant

Custom Home Assistant integration for receiving ekey UDP packets and exposing them as Home Assistant events.

The integration listens for local UDP packets in this format:

```text
1_<user_id>_<finger_id>_<reader_id>_<action>
```

Example:

```text
1_100001_7_12345678901234_900001
```

## Features

- UI installation through Home Assistant's integration wizard.
- Event entity for all fingerprints and optional reader-specific event entities.
- Home Assistant events for allowed, denied, and suspicious packets.
- Source IP or CIDR allowlist.
- Strict packet parsing with full payload matching.
- Duplicate suppression.
- Per-source rate limiting.
- Optional user, reader, action, and access-rule naming.

## Installation

### Manual

Copy `custom_components/ekey_udp` into your Home Assistant `custom_components` directory and restart Home Assistant.

### HACS custom repository

Add this repository as a custom repository in HACS:

```text
https://github.com/hypnosiss/ekey-udp-home-assistant
```

Category: Integration.

## Setup

1. In Home Assistant, go to **Settings > Devices & services**.
2. Select **Add integration**.
3. Search for **ekey UDP**.
4. Configure:
   - **Bind address**: usually `0.0.0.0`.
   - **UDP port**: default `51234`.
   - **Allowed source IPs or CIDR networks**: recommended. Example: `192.0.2.10`.
   - **Duplicate suppression window**: default `2`.
   - **Maximum packets per minute per source**: default `60`.

After setup, open the integration options to configure reader names, user names, action names, and access rules.

## Options JSON

The options screen accepts JSON strings for advanced mappings.

Readers:

```json
{
  "12345678901234": "front_door",
  "12345678901235": "gate"
}
```

Actions:

```json
{
  "900001": "accepted",
  "900002": "accepted"
}
```

Users:

```json
{
  "100001": {
    "name": "Alice"
  }
}
```

Finger numbers do not need aliases. If `fingers` is omitted for a user, the integration keeps the raw finger number, for example `"7"` or `"8"`.

Access rules:

```json
[
  {
    "id": "front_door",
    "name": "Front door",
    "readers": ["front_door"],
    "actions": ["accepted"],
    "users": ["Alice"],
    "fingers": ["7"]
  }
]
```

## Events

### `ekey_udp_event`

Fired for every valid packet.

Example event data:

```json
{
  "user_id": "100001",
  "user_name": "Alice",
  "finger_id": "7",
  "finger_name": "7",
  "reader_id": "12345678901234",
  "reader_name": "front_door",
  "action": "900001",
  "action_name": "accepted",
  "allowed": true,
  "access_id": "front_door",
  "access_ids": ["front_door"],
  "source_ip": "192.0.2.10"
}
```

### `ekey_udp_denied`

Fired when a valid packet does not match any access rule.

### `ekey_udp_suspicious`

Fired when a packet is rejected because of an unauthorized source, invalid packet format, or rate limiting.

## Automation Example

```yaml
alias: Open front door
trigger:
  - platform: event
    event_type: ekey_udp_event
    event_data:
      access_id: front_door
action:
  - service: switch.turn_on
    target:
      entity_id: switch.front_door
```

## Security Notes

ekey UDP packets are not cryptographically authenticated by this integration. If an attacker can send packets to the Home Assistant UDP port, they may be able to spoof events.

Recommended hardening:

- Set **Allowed source IPs or CIDR networks** to the ekey device IP only.
- Add a firewall rule that allows UDP traffic to the configured port only from the ekey device.
- Keep ekey and Home Assistant on a trusted IoT VLAN.
- Do not expose the UDP port outside the local network.
- Use access rules that match reader, action, user, and finger together.

This integration reduces spoofing risk with source filtering, strict parsing, duplicate suppression, and rate limiting, but it cannot provide cryptographic replay protection for unsigned UDP packets.

## Development

Run a syntax check:

```bash
python3 -m compileall custom_components/ekey_udp
```

## License

MIT
