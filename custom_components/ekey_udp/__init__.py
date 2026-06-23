"""Receive ekey UDP packets and expose them as Home Assistant events."""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
import json
import logging
import re
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PORT, Platform
from homeassistant.core import HomeAssistant

from .const import (
    CONF_ACCESS,
    CONF_ACCESS_JSON,
    CONF_ACTIONS,
    CONF_ACTIONS_JSON,
    CONF_ALLOWED_SOURCES,
    CONF_DEDUPE_SECONDS,
    CONF_FINGERS,
    CONF_MAX_PACKETS_PER_MINUTE,
    CONF_READERS,
    CONF_READERS_JSON,
    CONF_USERS,
    CONF_USERS_JSON,
    DEFAULT_DEDUPE_SECONDS,
    DEFAULT_HOST,
    DEFAULT_MAX_PACKETS_PER_MINUTE,
    DEFAULT_PORT,
    DENIED_EVENT_TYPE,
    DOMAIN,
    EVENT_TYPE,
    SUSPICIOUS_EVENT_TYPE,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = [Platform.EVENT]

PACKET_RE = re.compile(r"^1_(\d{6})_(\d)_(\d{14})_(\d{6})$")
RATE_WINDOW_SECONDS = 60.0


@dataclass(slots=True)
class RuntimeData:
    """Runtime state shared with the event platform."""

    config: dict[str, Any]
    listeners: list[Callable[[dict[str, Any]], None]]
    transport: asyncio.DatagramTransport | None


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ekey UDP listener from a config entry."""
    config = _build_runtime_config(entry)
    runtime = RuntimeData(config=config, listeners=[], transport=None)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = runtime

    dedupe_seconds = config[CONF_DEDUPE_SECONDS]
    last_seen: dict[tuple[str, str, str, str], float] = {}
    source_packets: dict[str, deque[float]] = defaultdict(deque)
    allowed_networks = [
        ip_network(source, strict=False) for source in config[CONF_ALLOWED_SOURCES]
    ]

    def source_allowed(source_ip: str) -> bool:
        if not allowed_networks:
            return True
        address = ip_address(source_ip)
        return any(address in network for network in allowed_networks)

    def fire_suspicious(reason: str, addr: tuple[str, int], raw: str | None = None) -> None:
        event = {
            "reason": reason,
            "source_ip": addr[0],
            "source_port": addr[1],
        }
        if raw is not None:
            event["raw"] = raw
        hass.bus.async_fire(SUSPICIOUS_EVENT_TYPE, event)

    def fire_packet(packet: dict[str, Any]) -> None:
        hass.bus.async_fire(EVENT_TYPE, packet)
        if not packet["allowed"]:
            hass.bus.async_fire(DENIED_EVENT_TYPE, packet)
        for listener in list(runtime.listeners):
            listener(packet)

    def matching_access_rules(packet: dict[str, Any]) -> list[dict[str, str]]:
        matches = []
        for rule in config[CONF_ACCESS]:
            if "readers" in rule and packet["reader_name"] not in rule["readers"]:
                continue
            if "users" in rule and packet["user_name"] not in rule["users"]:
                continue
            if "fingers" in rule and packet["finger_name"] not in rule["fingers"]:
                continue
            if "actions" in rule and packet["action_name"] not in rule["actions"]:
                continue
            matches.append({"id": rule["id"], "name": rule.get("name", rule["id"])})
        return matches

    class EkeyDatagramProtocol(asyncio.DatagramProtocol):
        """Async UDP protocol for ekey datagrams."""

        def connection_made(self, transport: asyncio.BaseTransport) -> None:
            runtime.transport = transport  # type: ignore[assignment]
            _LOGGER.info(
                "Listening for ekey UDP packets on %s:%s",
                config[CONF_HOST],
                config[CONF_PORT],
            )

        def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
            now = time.monotonic()
            raw = data.decode("utf-8", errors="replace").strip()

            try:
                if not source_allowed(addr[0]):
                    _LOGGER.warning("Rejected ekey UDP packet from unauthorized source %s", addr[0])
                    fire_suspicious("unauthorized_source", addr, raw)
                    return
            except ValueError:
                _LOGGER.warning("Rejected ekey UDP packet from invalid source %s", addr[0])
                fire_suspicious("invalid_source", addr, raw)
                return

            packets = source_packets[addr[0]]
            while packets and now - packets[0] > RATE_WINDOW_SECONDS:
                packets.popleft()
            if len(packets) >= config[CONF_MAX_PACKETS_PER_MINUTE]:
                _LOGGER.warning("Rate limited ekey UDP packets from %s", addr[0])
                fire_suspicious("rate_limited", addr, raw)
                return
            packets.append(now)

            match = PACKET_RE.fullmatch(raw)
            if not match:
                _LOGGER.debug("Ignoring unrecognized ekey UDP packet from %s: %r", addr, raw)
                fire_suspicious("invalid_packet", addr, raw)
                return

            user_id, finger_id, reader_id, action = match.groups()
            dedupe_key = (user_id, action, reader_id, finger_id)
            previous = last_seen.get(dedupe_key)
            if previous is not None and now - previous < dedupe_seconds:
                _LOGGER.debug("Ignoring duplicate ekey UDP packet: %s", dedupe_key)
                return

            last_seen[dedupe_key] = now
            user = config[CONF_USERS].get(user_id, {})
            packet = {
                "user_id": user_id,
                "user_name": user.get("name", user_id),
                "action": action,
                "action_name": config[CONF_ACTIONS].get(action, action),
                "reader_id": reader_id,
                "reader_name": config[CONF_READERS].get(reader_id, reader_id),
                "finger_id": finger_id,
                "finger_name": user.get(CONF_FINGERS, {}).get(finger_id, finger_id),
                "raw": raw,
                "source_ip": addr[0],
                "source_port": addr[1],
            }
            access_rules = matching_access_rules(packet)
            packet["allowed"] = bool(access_rules)
            packet["access_ids"] = [rule["id"] for rule in access_rules]
            packet["access_names"] = [rule["name"] for rule in access_rules]
            packet["access_id"] = packet["access_ids"][0] if access_rules else None
            packet["access_name"] = packet["access_names"][0] if access_rules else None

            log_method = _LOGGER.info if packet["allowed"] else _LOGGER.warning
            log_method(
                "Received ekey fingerprint: allowed=%s, access=%s, user=%s (%s), finger=%s (%s), reader=%s (%s), action=%s (%s)",
                packet["allowed"],
                packet["access_ids"],
                packet["user_id"],
                packet["user_name"],
                packet["finger_id"],
                packet["finger_name"],
                packet["reader_id"],
                packet["reader_name"],
                packet["action"],
                packet["action_name"],
            )
            fire_packet(packet)

        def error_received(self, exc: Exception) -> None:
            _LOGGER.warning("Error from ekey UDP socket: %s", exc)

    loop = asyncio.get_running_loop()
    try:
        transport, _protocol = await loop.create_datagram_endpoint(
            EkeyDatagramProtocol,
            local_addr=(config[CONF_HOST], config[CONF_PORT]),
        )
    except OSError:
        _LOGGER.exception(
            "Unable to bind ekey UDP listener on %s:%s",
            config[CONF_HOST],
            config[CONF_PORT],
        )
        hass.data[DOMAIN].pop(entry.entry_id, None)
        return False

    runtime.transport = transport
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload an ekey UDP config entry."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    runtime: RuntimeData | None = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if runtime and runtime.transport is not None:
        runtime.transport.close()
        runtime.transport = None
    return unload_ok


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the entry when options change."""
    await hass.config_entries.async_reload(entry.entry_id)


def _build_runtime_config(entry: ConfigEntry) -> dict[str, Any]:
    values = {**entry.data, **entry.options}
    return {
        CONF_HOST: values.get(CONF_HOST, DEFAULT_HOST),
        CONF_PORT: values.get(CONF_PORT, DEFAULT_PORT),
        CONF_DEDUPE_SECONDS: values.get(CONF_DEDUPE_SECONDS, DEFAULT_DEDUPE_SECONDS),
        CONF_MAX_PACKETS_PER_MINUTE: values.get(
            CONF_MAX_PACKETS_PER_MINUTE, DEFAULT_MAX_PACKETS_PER_MINUTE
        ),
        CONF_ALLOWED_SOURCES: values.get(CONF_ALLOWED_SOURCES, []),
        CONF_READERS: _json_value(values.get(CONF_READERS_JSON), {}),
        CONF_ACTIONS: _json_value(values.get(CONF_ACTIONS_JSON), {}),
        CONF_USERS: _json_value(values.get(CONF_USERS_JSON), {}),
        CONF_ACCESS: _json_value(values.get(CONF_ACCESS_JSON), []),
    }


def _json_value(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)
