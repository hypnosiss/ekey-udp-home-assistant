"""Constants for the ekey UDP integration."""

from __future__ import annotations

DOMAIN = "ekey_udp"

EVENT_TYPE = f"{DOMAIN}_event"
DENIED_EVENT_TYPE = f"{DOMAIN}_denied"
SUSPICIOUS_EVENT_TYPE = f"{DOMAIN}_suspicious"

CONF_ACCESS = "access"
CONF_ACCESS_JSON = "access_json"
CONF_ACTIONS = "actions"
CONF_ACTIONS_JSON = "actions_json"
CONF_ALLOWED_SOURCES = "allowed_sources"
CONF_ALLOWED_SOURCES_TEXT = "allowed_sources_text"
CONF_DEDUPE_SECONDS = "dedupe_seconds"
CONF_FINGERS = "fingers"
CONF_MAX_PACKETS_PER_MINUTE = "max_packets_per_minute"
CONF_READERS = "readers"
CONF_READERS_JSON = "readers_json"
CONF_USERS = "users"
CONF_USERS_JSON = "users_json"

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 51234
DEFAULT_DEDUPE_SECONDS = 2.0
DEFAULT_MAX_PACKETS_PER_MINUTE = 60

PACKET_FORMAT = "1_<user_id>_<finger_id>_<reader_id>_<action>"
