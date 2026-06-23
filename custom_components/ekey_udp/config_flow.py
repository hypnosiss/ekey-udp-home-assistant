"""Config flow for the ekey UDP integration."""

from __future__ import annotations

from ipaddress import ip_network
import json
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.core import callback

from .const import (
    CONF_ACCESS_JSON,
    CONF_ACTIONS_JSON,
    CONF_ALLOWED_SOURCES,
    CONF_ALLOWED_SOURCES_TEXT,
    CONF_DEDUPE_SECONDS,
    CONF_MAX_PACKETS_PER_MINUTE,
    CONF_READERS_JSON,
    CONF_USERS_JSON,
    DEFAULT_DEDUPE_SECONDS,
    DEFAULT_HOST,
    DEFAULT_MAX_PACKETS_PER_MINUTE,
    DEFAULT_PORT,
    DOMAIN,
)


class EkeyUdpConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle an ekey UDP config flow."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Handle the initial step."""
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                sources = _parse_sources(user_input.get(CONF_ALLOWED_SOURCES_TEXT, ""))
            except ValueError:
                errors[CONF_ALLOWED_SOURCES_TEXT] = "invalid_sources"
            else:
                await self.async_set_unique_id(f"{user_input[CONF_HOST]}:{user_input[CONF_PORT]}")
                self._abort_if_unique_id_configured()
                data = {
                    CONF_HOST: user_input[CONF_HOST],
                    CONF_PORT: user_input[CONF_PORT],
                    CONF_DEDUPE_SECONDS: user_input[CONF_DEDUPE_SECONDS],
                    CONF_MAX_PACKETS_PER_MINUTE: user_input[CONF_MAX_PACKETS_PER_MINUTE],
                    CONF_ALLOWED_SOURCES: sources,
                }
                return self.async_create_entry(title="ekey UDP", data=data)

        return self.async_show_form(
            step_id="user",
            data_schema=_user_schema(user_input),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> EkeyUdpOptionsFlow:
        """Create the options flow."""
        return EkeyUdpOptionsFlow(config_entry)


class EkeyUdpOptionsFlow(config_entries.OptionsFlow):
    """Handle ekey UDP options."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        """Initialize options flow."""
        self._config_entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> config_entries.ConfigFlowResult:
        """Manage integration options."""
        errors: dict[str, str] = {}
        if user_input is not None:
            for key in (
                CONF_READERS_JSON,
                CONF_ACTIONS_JSON,
                CONF_USERS_JSON,
                CONF_ACCESS_JSON,
            ):
                try:
                    json.loads(user_input.get(key) or "{}")
                except json.JSONDecodeError:
                    errors[key] = "invalid_json"
            try:
                sources = _parse_sources(user_input.get(CONF_ALLOWED_SOURCES_TEXT, ""))
            except ValueError:
                errors[CONF_ALLOWED_SOURCES_TEXT] = "invalid_sources"

            if not errors:
                options = {
                    CONF_DEDUPE_SECONDS: user_input[CONF_DEDUPE_SECONDS],
                    CONF_MAX_PACKETS_PER_MINUTE: user_input[CONF_MAX_PACKETS_PER_MINUTE],
                    CONF_ALLOWED_SOURCES: sources,
                    CONF_READERS_JSON: user_input.get(CONF_READERS_JSON, ""),
                    CONF_ACTIONS_JSON: user_input.get(CONF_ACTIONS_JSON, ""),
                    CONF_USERS_JSON: user_input.get(CONF_USERS_JSON, ""),
                    CONF_ACCESS_JSON: user_input.get(CONF_ACCESS_JSON, ""),
                }
                return self.async_create_entry(title="", data=options)

        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(self._config_entry, user_input),
            errors=errors,
        )


def _user_schema(user_input: dict[str, Any] | None) -> vol.Schema:
    user_input = user_input or {}
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=user_input.get(CONF_HOST, DEFAULT_HOST)): str,
            vol.Required(CONF_PORT, default=user_input.get(CONF_PORT, DEFAULT_PORT)): int,
            vol.Optional(
                CONF_ALLOWED_SOURCES_TEXT,
                default=user_input.get(CONF_ALLOWED_SOURCES_TEXT, ""),
            ): str,
            vol.Required(
                CONF_DEDUPE_SECONDS,
                default=user_input.get(CONF_DEDUPE_SECONDS, DEFAULT_DEDUPE_SECONDS),
            ): float,
            vol.Required(
                CONF_MAX_PACKETS_PER_MINUTE,
                default=user_input.get(
                    CONF_MAX_PACKETS_PER_MINUTE, DEFAULT_MAX_PACKETS_PER_MINUTE
                ),
            ): int,
        }
    )


def _options_schema(
    config_entry: config_entries.ConfigEntry, user_input: dict[str, Any] | None
) -> vol.Schema:
    values = {**config_entry.data, **config_entry.options, **(user_input or {})}
    return vol.Schema(
        {
            vol.Optional(
                CONF_ALLOWED_SOURCES_TEXT,
                default=values.get(
                    CONF_ALLOWED_SOURCES_TEXT,
                    ", ".join(values.get(CONF_ALLOWED_SOURCES, [])),
                ),
            ): str,
            vol.Required(
                CONF_DEDUPE_SECONDS,
                default=values.get(CONF_DEDUPE_SECONDS, DEFAULT_DEDUPE_SECONDS),
            ): float,
            vol.Required(
                CONF_MAX_PACKETS_PER_MINUTE,
                default=values.get(
                    CONF_MAX_PACKETS_PER_MINUTE, DEFAULT_MAX_PACKETS_PER_MINUTE
                ),
            ): int,
            vol.Optional(CONF_READERS_JSON, default=values.get(CONF_READERS_JSON, "")): str,
            vol.Optional(CONF_ACTIONS_JSON, default=values.get(CONF_ACTIONS_JSON, "")): str,
            vol.Optional(CONF_USERS_JSON, default=values.get(CONF_USERS_JSON, "")): str,
            vol.Optional(CONF_ACCESS_JSON, default=values.get(CONF_ACCESS_JSON, "")): str,
        }
    )


def _parse_sources(value: str) -> list[str]:
    sources = []
    for source in value.split(","):
        source = source.strip()
        if not source:
            continue
        ip_network(source, strict=False)
        sources.append(source)
    return sources
