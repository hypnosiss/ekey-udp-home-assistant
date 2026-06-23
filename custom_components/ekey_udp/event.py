"""Event entities for ekey UDP."""

from __future__ import annotations

from typing import Any

from homeassistant.components.event import EventEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_READERS, DOMAIN
from . import RuntimeData


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up event entities from a config entry."""
    runtime: RuntimeData = hass.data[DOMAIN][entry.entry_id]
    readers = runtime.config.get(CONF_READERS, {})

    entities = [
        EkeyUdpEventEntity("any", "Any fingerprint", runtime),
        *[
            EkeyUdpEventEntity(reader_id, reader_name, runtime)
            for reader_id, reader_name in readers.items()
        ],
    ]
    async_add_entities(entities)


class EkeyUdpEventEntity(EventEntity):
    """Represent latest ekey fingerprint event."""

    _attr_event_types = ["fingerprint"]

    def __init__(self, reader_id: str, name: str, runtime: RuntimeData) -> None:
        """Initialize the event entity."""
        self._reader_id = reader_id
        self._attr_name = f"ekey {name}"
        self._attr_unique_id = f"ekey_udp_{reader_id}"
        self._runtime = runtime
        runtime.listeners.append(self._handle_packet)

    async def async_will_remove_from_hass(self) -> None:
        """Remove the runtime packet listener."""
        self._runtime.listeners.remove(self._handle_packet)

    @callback
    def _handle_packet(self, packet: dict[str, Any]) -> None:
        """Trigger entity event when a matching packet is received."""
        if self._reader_id != "any" and packet["reader_id"] != self._reader_id:
            return

        self._trigger_event("fingerprint", packet)
        self.async_write_ha_state()
