# See:
# https://govee-public.s3.amazonaws.com/developer-docs/GoveeDeveloperAPIReference.pdf
# https://app-h5.govee.com/user-manual/wlan-guide
# https://github.com/egold555/Govee-Reverse-Engineering/blob/master/Products/H6127.md

import asyncio
from .aws import (
    aws_get_supported_scenes,
    GoveeAWSSceneDefinition,
    GoveeAWSListener,
)
from copy import copy, deepcopy
from dataclasses import dataclass
import json
import logging
import socket
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from bleak import BleakScanner, BLEDevice
from bleak.exc import BleakError

from .ble import BleDeviceEntry, GoveeBlePacket, is_govee_device
from .color import GoveeColor
from .http import (
    GoveeHttpDeviceDefinition,
    http_device_control,
    http_get_devices,
    http_get_state,
)
from .models import ModelInfo
from .models import HttpSceneMode
from .scene import GoveeScene
from .scene import GoveeSceneList

BROADCAST_PORT = 4001
COMMAND_PORT = 4003
LISTEN_PORT = 4002
BROADCAST_ADDR = "239.255.255.250"
BLE_IDLE_INTERVAL = 60
BLE_DISCOVER_INTERVAL = 600

_LOGGER = logging.getLogger(__name__)


@dataclass
class GoveeDeviceState:
    """Represents the controllable attribute state of the device"""

    turned_on: bool = False
    brightness_pct: int = 0
    color: Optional[GoveeColor] = None
    color_temperature: Optional[int] = None
    scene: Optional[GoveeScene] = None

    def __repr__(self):
        return str(self.__dict__)


@dataclass
class GoveeLanDeviceDefinition:
    """Device information, available via LAN API"""

    ip_addr: str
    device_id: str
    model: str
    ble_hardware_version: str
    ble_software_version: str
    wifi_hardware_version: str
    wifi_software_version: str


class GoveeDevice:
    """Represents a device, identified by its device_id"""

    state: Optional[GoveeDeviceState] = None
    http_definition: Optional[GoveeHttpDeviceDefinition] = None
    lan_definition: Optional[GoveeLanDeviceDefinition] = None
    ble_device: Optional[BLEDevice] = None
    device_id: str
    model: str

    def __init__(self, device_id: str, model: str):
        self.device_id = device_id
        self.model = model

    def __repr__(self):
        return str(self.__dict__)


class GoveeHttpCommand:
    """An HTTP command. Structure is dependent on the device/model"""

    def __init__(self):
        self.params = {}

    @staticmethod
    def power(device: GoveeDevice, is_on: bool, is_lan: bool) -> Dict:
        if is_lan:
            return {
                "msg": {
                    "cmd": "turn",
                    "data": {"value": 1 if is_on else 0},
                }
            }
        else:
            return {
                "device": device.device_id,
                "model": device.model,
                "cmd": {
                    "name": "turn",
                    "value": "on" if is_on else "off",
                },
            }

    @staticmethod
    def brightness(device: GoveeDevice, brightness_pct: int, is_lan: bool) -> Dict:
        if is_lan:
            return {
                "msg": {
                    "cmd": "brightness",
                    "data": {"value": brightness_pct},
                }
            }
        else:
            return {
                "device": device.device_id,
                "model": device.model,
                "cmd": {
                    "name": "brightness",
                    "value": brightness_pct,
                },
            }

    @staticmethod
    def rgb_color(device: GoveeDevice, color: GoveeColor, is_lan: bool) -> Dict:
        if is_lan:
            return {
                "msg": {
                    "cmd": "colorwc",
                    "data": {
                        "color": color.as_json_object(),
                    },
                }
            }
        else:
            return {
                "device": device.device_id,
                "model": device.model,
                "cmd": {
                    "name": "color",
                    "value": color.as_json_object(),
                },
            }

    @staticmethod
    def color_temperature(
        device: GoveeDevice, color_temperature: int, is_lan: bool
    ) -> Dict:
        if is_lan:
            return {
                "msg": {
                    "cmd": "colorwc",
                    "data": {
                        "colorTemInKelvin": color_temperature,
                    },
                }
            }
        else:
            return {
                "device": device.device_id,
                "model": device.model,
                "cmd": {
                    "name": "colorTem",
                    "value": color_temperature,
                },
            }

    @staticmethod
    def scene(device: GoveeDevice, scene: GoveeScene, is_lan: bool) -> Dict:
        # scene commands depend on the model: either "pt" with command "op" or "ptReal"
        # scenes are not supported by the govee API, but can be set over BLE or by AWS
        # TODO over AWS IOT (not currently implemented in govee-led-wez)
        model_info = ModelInfo.resolve(device.model)
        cmd = "ptReal"
        if model_info.http_scene_mode == HttpSceneMode.MODE_OP:
            cmd = "pt"
        if is_lan:
            return {
                "msg": {
                    "cmd": cmd,
                    "data": {"command": scene.lanCode, "op": "mode"},
                }
            }
        else:
            raise RuntimeError("Scenes API or AWS IOT are not implemented")
            return {
                "device": device.device_id,
                "model": device.model,
                "cmd": {
                    "name": cmd,
                    "op": "mode",
                    "value": scene.lanCode,
                },
            }

    @staticmethod
    def status(is_lan: bool):
        if is_lan:
            return {
                "msg": {
                    "cmd": "devStatus",
                    "data": {},
                }
            }
        else:
            pass


# Type for device changed event callback
DeviceUpdated = Callable[[GoveeDevice], None]


class GoveeController:
    """Manages a set of lights"""

    api_key: Optional[str] = None
    email: Optional[str] = None
    password: Optional[str] = None
    on_device_changed: Optional[DeviceUpdated] = None
    ble_poller: Optional[asyncio.Task] = None
    ble_idler: Optional[asyncio.Task] = None
    http_poller: Optional[asyncio.Task] = None
    lan_pollers: List[asyncio.Task]
    lan_source_address: Optional[str] = None
    http_devices: Dict[str, GoveeHttpDeviceDefinition]
    ble_devices: Dict[str, BleDeviceEntry]
    devices: Dict[str, GoveeDevice]
    waiting_for_status: Dict[str, List[asyncio.Future]]
    device_control_timeout: int = 10

    def __init__(self):
        self.ble_devices = {}
        self.http_devices = {}
        self.lan_pollers = []
        self.devices = {}
        self.waiting_for_status = {}

    def set_http_api_key(self, api_key: str):
        """Sets the API for use with the HTTP API"""
        self.api_key = api_key

    def set_aws_email(self, email: str):
        """Sets the API for use with the AWS API"""
        self.email = email

    def set_aws_password(self, password: str):
        """Sets the API for use with the AWS API"""
        self.password = password

    def set_device_control_timeout(self, timeout: int):
        """Sets the timeout duration for making control requests"""
        self.device_control_timeout = timeout

    def set_device_change_callback(self, on_change: DeviceUpdated):
        """Sets the callback that will receive updated device notifications"""
        self.on_device_changed = on_change

    async def start_aws_listener(self):
        if self.email is None:
            raise RuntimeError("email is required to use the aws api")
        if self.password is None:
            raise RuntimeError("password is required to use the aws api")
        _awsListener = GoveeAWSListener(self.email, self.password)
        await _awsListener.login()
        await _awsListener.connect()
        await _awsListener.logout()

    def start_lan_poller(
        self, interfaces: Optional[List[str]] = None, interval: float = 10
    ):
        """Start listening for LAN protocol responses on the given set
        of interfaces.  Will attempt to discover new devices every
        interval seconds"""
        if self.lan_pollers:
            raise RuntimeError("lan poller is already running")

        interfaces = interfaces or ["0.0.0.0"]
        for iface in interfaces:
            if self.lan_source_address:
                # we're on a multi-homed system; we don't currently
                # know enough to handle this correctly, so shrug for now.
                # Handling this correctly would mean capturing the complete
                # set of interfaces and then changing the sendto logic to
                # try to match the correct one based on the destination IP
                # address.
                self.lan_source_address = None
            else:
                self.lan_source_address = iface
            self.lan_pollers.append(
                asyncio.create_task(self._lan_poller(iface, interval))
            )

    def start_http_poller(self, interval: int = 600):
        """Start a task to discover devices via the HTTP API.
        New devices will be discovered every interval seconds.
        This does NOT poll individual devices"""
        if self.api_key is None:
            raise RuntimeError("api_key is required to use the HTTP api")
        if self.http_poller:
            raise RuntimeError("http poller is already running")
        self.http_poller = asyncio.create_task(self._http_poller(interval))

    def start_ble_poller(self, interval: int = BLE_DISCOVER_INTERVAL):
        """Start a task to discover devices via bluetooth.
        New devices will be discovered every interval seconds.
        This does NOT poll individual devices"""
        if self.ble_poller:
            raise RuntimeError("ble poller is already running")
        self.ble_poller = asyncio.create_task(self._ble_poller(interval))

    def start_ble_idler(self, interval: int = BLE_IDLE_INTERVAL):
        """Start a task to disconnect from ble devices after
        they are idle for a while"""
        if self.ble_idler:
            raise RuntimeError("ble idler is already running")
        self.ble_idler = asyncio.create_task(self._ble_idler(interval))

    async def _ble_idler(self, interval: int):
        while True:
            await asyncio.sleep(interval)
            await self.disconnect_idle_ble_devices(interval)

    async def _ble_poller(self, interval: int):
        while True:
            await self.query_ble_devices()
            await asyncio.sleep(interval)

    def _get_device_by_ble_address(self, address: str) -> Optional[GoveeDevice]:
        for device in self.devices.values():
            if device.device_id.endswith(address):
                return device
        return None

    def register_ble_device(self, ble_device: BLEDevice):
        """Registers a known-Govee bluetooth device by its address"""
        changed = False

        if entry := self.ble_devices.get(ble_device.address, None):
            # Update the device to the latest version provided by the caller
            if entry.device != ble_device:
                changed = True
            entry.device = ble_device
        else:
            entry = BleDeviceEntry(ble_device)
            self.ble_devices[ble_device.address] = entry
            changed = True

        # We don't have enough information available via BLE
        # to synthesize new, complete devices just from BLE,
        # so this only associates with devices we've found via
        # HTTP or LAN.
        # NOTE: we COULD do this, if we generated a placeholder
        # with just the BLE info, then swizzled it out later
        if dev := self._get_device_by_ble_address(ble_device.address):
            if dev.ble_device is None or dev.ble_device != ble_device:
                dev.ble_device = ble_device
                changed = True
                _LOGGER.debug(
                    "Updating BLE device association for %s with %s",
                    ble_device.address,
                    dev.device_id,
                )
            if changed:
                self._fire_device_change(dev)

    async def query_ble_devices(self) -> List[BLEDevice]:
        """Make an immediate call to the ble scanner to enumerate
        bluetooth devices. Filters the list to those for which
        is_govee_device returns true.
        Registers the devices in the controller state, and returns
        the underlying BLEDevice for each discovered Govee ble device"""
        result = []
        ble_devices = await BleakScanner.discover(return_adv=True)
        for device, adv in ble_devices.values():
            if not is_govee_device(adv):
                continue
            self.register_ble_device(device)
            result.append(device)

        return result

    async def query_http_devices(self) -> List[GoveeHttpDeviceDefinition]:
        """Make an immediate call to the HTTP API to list available devices"""
        """All devices controllabel by http api WILL also be controllable by AWS"""
        if self.api_key is None:
            raise RuntimeError("api_key is required to use the HTTP api")
        devices = await http_get_devices(self.api_key)
        self.http_devices = {dev.device_id: dev for dev in devices}

        for definition in devices:
            if dev := self.devices.get(definition.device_id, None):
                dev.http_definition = definition
                if self._match_devices(dev):
                    self._fire_device_change(dev)
            else:
                # Newly discovered
                dev = GoveeDevice(definition.device_id, definition.model)
                dev.http_definition = definition
                self.devices[dev.device_id] = dev
                self._match_devices(dev)
                self._fire_device_change(dev)

        return devices

    async def query_aws_scenes(self) -> List[GoveeScene]:
        """Make an immediate call to the HTTP API to list available scenes"""
        if self.api_key is None:
            raise RuntimeError("api_key is required to use the HTTP api")
        if self.password is None:
            raise RuntimeError(
                "password is required to use scenes through the HTTP api"
            )
        if self.email is None:
            raise RuntimeError(
                "email/username is required to use scenes through the HTTP api"
            )

        return None

    def get_device_by_id(self, device_id: str) -> Optional[GoveeDevice]:
        """Returns the device that corresponds to a given device_id,
        if known"""
        return self.devices.get(device_id, None)

    def _send_lan_command(self, lan_definition: GoveeLanDeviceDefinition, cmd: Any):
        data = bytes(json.dumps(cmd), "utf-8")
        dgram_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.lan_source_address:
            dgram_socket.bind((self.lan_source_address, 0))
        dgram_socket.sendto(data, (lan_definition.ip_addr, COMMAND_PORT))

    def _request_lan_status(self, lan_definition: GoveeLanDeviceDefinition):
        self._send_lan_command(lan_definition, GoveeHttpCommand.status(True))

    def _complete_lan_futures(self, device: GoveeDevice):
        if futures := self.waiting_for_status.get(device.device_id, None):
            futures_copied = copy(futures)
            for future in futures_copied:
                if not future.cancelled():
                    future.set_result(None)
                futures.remove(future)

    async def update_device_state(self, device: GoveeDevice) -> GoveeDeviceState:
        """Fetches the current state of device, updating its state
        property and triggering the device changed event if
        appropriate"""

        if device.lan_definition:
            future = asyncio.get_event_loop().create_future()
            try:
                if device.device_id not in self.waiting_for_status:
                    self.waiting_for_status[device.device_id] = []
                self.waiting_for_status[device.device_id].append(future)
                self._request_lan_status(device.lan_definition)
                await asyncio.wait_for(future, timeout=self.device_control_timeout)
                assert device.state is not None
                return device.state

            finally:
                try:
                    self.waiting_for_status[device.device_id].remove(future)
                except ValueError:
                    pass

        if self.api_key:
            properties = await asyncio.wait_for(
                http_get_state(self.api_key, device.device_id, device.model),
                timeout=self.device_control_timeout,
            )

            turned_on = False
            brightness_pct = 100
            color: Optional[GoveeColor] = None
            color_temperature: Optional[int] = None

            for prop in properties:
                if "powerState" in prop:
                    turned_on = prop["powerState"] == "on"
                if "brightness" in prop:
                    brightness_pct = prop["brightness"]
                if "color" in prop:
                    color = GoveeColor(
                        red=prop["color"]["r"],
                        green=prop["color"]["g"],
                        blue=prop["color"]["b"],
                    )
                if "colorTem" in prop:
                    color_temperature = (
                        None if prop["colorTem"] == 0 else prop["colorTem"]
                    )

            state = GoveeDeviceState(
                turned_on, brightness_pct, color, color_temperature
            )
            changed = state != device.state
            if changed:
                device.state = state
                self._fire_device_change(device)
            assert device.state is not None
            return device.state

        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def disconnect_idle_ble_devices(
        self, idle_time: int = BLE_IDLE_INTERVAL
    ) -> int:
        """Disconnect any ble devices that have not been used within
        the last idle_time seconds"""
        now = time.monotonic()
        count = 0
        for entry in self.ble_devices.values():
            if entry.last_use is not None and now - entry.last_use >= idle_time:
                await entry.disconnect()
                count += 1
        return count

    async def _disconnect_lru_ble_device(self) -> bool:
        lru = None
        for entry in self.ble_devices.values():
            if entry.last_use is not None:
                if lru is None:
                    lru = entry
                    continue
                if entry.last_use < lru.last_use:
                    lru = entry
                    continue

        if lru:
            await lru.disconnect()
            return True

        return False

    async def _ble_device_control(self, device: GoveeDevice, pkt: bytes):
        assert device.ble_device is not None
        entry = self.ble_devices[device.ble_device.address]
        error = None

        try:
            _LOGGER.debug("sending ble control to %s: %s", device.device_id, pkt)
            await entry.write_gatt_char(pkt)
            _LOGGER.debug("ble control was sent successfully")
            return
        except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
            error = exc
            _LOGGER.debug(
                "unable to connect to %s via BLE",
                device.device_id,
                exc_info=exc,
            )

        # We may have too many clients active; try to manage them
        if await self.disconnect_idle_ble_devices() > 0:
            # Make another attempt
            await entry.write_gatt_char(pkt)
            return

        # Try evicting the least recently used entry
        if await self._disconnect_lru_ble_device():
            # Make another attempt
            await entry.write_gatt_char(pkt)
            return

        raise error

    async def set_power_state(
        self, device: GoveeDevice, turned_on: bool
    ) -> GoveeDeviceState:
        """Set the power state for the specified device"""
        assumed_state = deepcopy(
            device.state
            or GoveeDeviceState(
                turned_on=True, brightness_pct=0, color=None, color_temperature=None
            )
        )
        assumed_state.turned_on = turned_on

        if device.lan_definition:
            device.state = assumed_state
            self._send_lan_command(
                device.lan_definition, GoveeHttpCommand.power(device, turned_on, True)
            )
            # We don't query the device right away: it can return
            # stale information immediately after we send the data,
            # and then not return any replies for a little while
            self._fire_device_change(device)
            return device.state

        if device.ble_device:
            pkt = GoveeBlePacket.power(turned_on)
            try:
                await asyncio.wait_for(
                    self._ble_device_control(device, pkt),
                    timeout=self.device_control_timeout,
                )
                device.state = assumed_state
                self._fire_device_change(device)
                return device.state
            except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
                _LOGGER.debug(
                    "unable to connect to %s via BLE, will use other methods",
                    device.device_id,
                    exc_info=exc,
                )

        if self.api_key and device.http_definition:
            if "turn" not in device.http_definition.supported_commands:
                raise RuntimeError("device doesn't support turn command")

            await asyncio.wait_for(
                http_device_control(
                    self.api_key, GoveeHttpCommand.power(device, turned_on, False)
                ),
                timeout=self.device_control_timeout,
            )
            device.state = assumed_state
            self._fire_device_change(device)
            return device.state

        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def set_color(
        self, device: GoveeDevice, color: GoveeColor
    ) -> GoveeDeviceState:
        """Set the color of the specified device.
        Implicitly turns the device on."""
        assumed_state = deepcopy(
            device.state
            or GoveeDeviceState(
                turned_on=True,
                brightness_pct=100,
                color=None,
                color_temperature=None,
            )
        )
        assumed_state.turned_on = True
        assumed_state.color = color
        assumed_state.color_temperature = None

        if device.lan_definition:
            device.state = assumed_state
            self._send_lan_command(
                device.lan_definition, GoveeHttpCommand.rgb_color(device, color, True)
            )
            # We don't query the device right away: it can return
            # stale information immediately after we send the data,
            # and then not return any replies for a little while
            self._fire_device_change(device)
            return device.state

        if device.ble_device:
            pkt = GoveeBlePacket.rgb_color(color, ModelInfo.resolve(device.model))
            try:
                await asyncio.wait_for(
                    self._ble_device_control(device, pkt),
                    timeout=self.device_control_timeout,
                )
                device.state = assumed_state
                self._fire_device_change(device)
                return device.state
            except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
                _LOGGER.debug(
                    "unable to connect to %s via BLE, will use other methods",
                    device.device_id,
                    exc_info=exc,
                )

        if self.api_key and device.http_definition:
            if "color" not in device.http_definition.supported_commands:
                raise RuntimeError("device doesn't support color command")

            await asyncio.wait_for(
                http_device_control(
                    self.api_key, GoveeHttpCommand.rgb_color(device, color, False)
                ),
                timeout=self.device_control_timeout,
            )
            device.state = assumed_state
            self._fire_device_change(device)
            return device.state

        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def set_color_temperature(
        self, device: GoveeDevice, color_temperature: int
    ) -> GoveeDeviceState:
        """Set the color temperature of the specified device.
        Implicitly turns the device on."""
        assumed_state = deepcopy(
            device.state
            or GoveeDeviceState(
                turned_on=True,
                brightness_pct=100,
                color=None,
                color_temperature=None,
            )
        )
        assumed_state.turned_on = True
        assumed_state.color = None
        assumed_state.color_temperature = color_temperature

        if device.lan_definition:
            device.state = assumed_state
            self._send_lan_command(
                device.lan_definition,
                GoveeHttpCommand.color_temperaturs(device, color_temperature, True),
            )
            # We don't query the device right away: it can return
            # stale information immediately after we send the data,
            # and then not return any replies for a little while
            self._fire_device_change(device)
            return device.state

        if device.ble_device:
            pkt = GoveeBlePacket.color_temperature(
                color_temperature, ModelInfo.resolve(device.model)
            )
            try:
                await asyncio.wait_for(
                    self._ble_device_control(device, pkt),
                    timeout=self.device_control_timeout,
                )
                device.state = assumed_state
                self._fire_device_change(device)
                return device.state
            except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
                _LOGGER.debug(
                    "unable to connect to %s via BLE, will use other methods",
                    device.device_id,
                    exc_info=exc,
                )

        if self.api_key and device.http_definition:
            if "colorTem" not in device.http_definition.supported_commands:
                raise RuntimeError("device doesn't support colorTem command")

            await asyncio.wait_for(
                http_device_control(
                    self.api_key,
                    GoveeHttpCommand.color_temperature(
                        device, color_temperature, False
                    ),
                ),
                timeout=self.device_control_timeout,
            )
            device.state = assumed_state
            self._fire_device_change(device)
            return device.state

        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def set_brightness(
        self, device: GoveeDevice, brightness_pct: int
    ) -> GoveeDeviceState:
        """Set the brightness of the specified device.
        Implicitly turns the device on"""
        assumed_state = deepcopy(
            device.state
            or GoveeDeviceState(
                turned_on=True,
                brightness_pct=100,
                color=None,
                color_temperature=None,
            )
        )
        assumed_state.turned_on = True
        assumed_state.brightness_pct = brightness_pct

        if device.lan_definition:
            device.state = assumed_state
            self._send_lan_command(
                device.lan_definition,
                GoveeHttpCommand.brightness(device, brightness_pct, True),
            )
            # We don't query the device right away: it can return
            # stale information immediately after we send the data,
            # and then not return any replies for a little while
            self._fire_device_change(device)
            return device.state

        if device.ble_device:
            pkt = GoveeBlePacket.brightness(
                brightness_pct, ModelInfo.resolve(device.model)
            )
            try:
                await asyncio.wait_for(
                    self._ble_device_control(device, pkt),
                    timeout=self.device_control_timeout,
                )
                device.state = assumed_state
                self._fire_device_change(device)
                return device.state
            except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
                _LOGGER.debug(
                    "unable to connect to %s via BLE, will use other methods",
                    device.device_id,
                    exc_info=exc,
                )

        if self.api_key and device.http_definition:
            if "brightness" not in device.http_definition.supported_commands:
                raise RuntimeError("device doesn't support brightness command")

            await asyncio.wait_for(
                http_device_control(
                    self.api_key,
                    GoveeHttpCommand.brightness(device, brightness_pct, False),
                ),
                timeout=self.device_control_timeout,
            )
            device.state = assumed_state
            self._fire_device_change(device)
            return device.state
        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def set_scene(
        self, device: GoveeDevice, scene: GoveeScene
    ) -> GoveeDeviceState:
        """Set the scene of the specified device.
        Implicitly turns the device on."""
        assumed_state = deepcopy(
            device.state
            or GoveeDeviceState(
                turned_on=True,
                brightness_pct=100,
                color=None,
                color_temperature=None,
                scene=None,
            )
        )
        assumed_state.turned_on = True
        assumed_state.color = None
        assumed_state.color_temperature = None
        assumed_state.scene = scene

        if device.ble_device:
            pkt = GoveeBlePacket.scene(scene, ModelInfo.resolve(device.model))
            try:
                await asyncio.wait_for(
                    self._ble_device_control(device, pkt),
                    timeout=self.device_control_timeout,
                )
                device.state = assumed_state
                self._fire_device_change(device)
                return device.state
            except (BleakError, asyncio.CancelledError, asyncio.TimeoutError) as exc:
                _LOGGER.debug(
                    "unable to connect to %s via BLE, will use other methods",
                    device.device_id,
                    exc_info=exc,
                )

        if self.email and self.password and device.http_definition:
            # scene commands are not supported by the api
            # however they are available via AWS IOT (see govee-homebridge)
            if "ptReal" not in device.http_definition.supported_commands:
                raise RuntimeError("device doesn't support scene commands via http API")

            await asyncio.wait_for(
                http_device_control(
                    self.api_key, GoveeHttpCommand.scene(device, scene, False)
                ),
                timeout=self.device_control_timeout,
            )
            device.state = assumed_state
            self._fire_device_change(device)
            return device.state

        raise RuntimeError("either call start_lan_poller or set_http_api_key")

    async def _http_poller(self, interval: int):
        while True:
            await self.query_http_devices()
            await asyncio.sleep(interval)

    async def _lan_poller(self, interface, interval: float):
        loop = asyncio.get_event_loop()
        transport, _protocol = await loop.create_datagram_endpoint(
            lambda: GoveeLanListener(self), local_addr=(interface, LISTEN_PORT)
        )
        try:
            mcast = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            mcast.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            mcast.setsockopt(
                socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(interface)
            )
            mcast.setsockopt(
                socket.SOL_IP,
                socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(BROADCAST_ADDR) + socket.inet_aton(interface),
            )
            mcast.bind((interface, 0))

            while True:
                mcast.sendto(
                    b'{"msg":{"cmd":"scan","data":{"account_topic":"reserve"}}}',
                    (BROADCAST_ADDR, BROADCAST_PORT),
                )
                await asyncio.sleep(interval)

        finally:
            transport.close()

    def _process_lan_scan(self, data: Dict[str, Any]):
        device = GoveeDevice(device_id=data["device"], model=data["sku"])
        device.lan_definition = GoveeLanDeviceDefinition(
            ip_addr=data["ip"],
            device_id=data["device"],
            model=data["sku"],
            ble_hardware_version=data["bleVersionHard"],
            ble_software_version=data["bleVersionSoft"],
            wifi_hardware_version=data["wifiVersionHard"],
            wifi_software_version=data["wifiVersionSoft"],
        )

        if existing := self.devices.get(device.device_id, None):
            changed = existing.lan_definition != device.lan_definition
            if changed:
                existing.lan_definition = device.lan_definition
            if self._match_devices(existing):
                changed = True
            if changed:
                self._fire_device_change(existing)
        else:
            # Newly discovered
            self.devices[device.device_id] = device
            self._match_devices(device)
            self._fire_device_change(device)

    def _process_lan_status(self, data: Dict[str, Any], addr: Tuple[str, int]):
        source_ip = addr[0]
        color = None
        if rgb := data.get("color", None):
            color = GoveeColor(
                red=rgb["r"],
                green=rgb["g"],
                blue=rgb["b"],
            )
        if op := data.get("op", None):
            if cmd := op.get("command", None):
                _LOGGER.debug("op command received, command params are %s", cmd)
            elif cmd := op.get("mode", None):
                _LOGGER.debug("op command received, mode params are %s", cmd)
            elif cmd := op.get("opcode", None):
                if mode := op.get("modeValue", None):
                    _LOGGER.debug("op command received, modeValue params are %s", mode)
        state = GoveeDeviceState(
            turned_on=data["onOff"] == 1,
            brightness_pct=data["brightness"],
            color=color,
            color_temperature=data.get("colorTemInKelvin", None),
        )
        """scene = GoveeScene TODO once scenes are supported by lan api if ever!!!"""
        for device in self.devices.values():
            if lan := device.lan_definition:
                if lan.ip_addr == source_ip:
                    changed = device.state != state
                    if changed:
                        device.state = state
                        self._fire_device_change(device)
                    else:
                        _LOGGER.debug(
                            "%s state is same as previous, skip callback",
                            device.device_id,
                        )

                    self._complete_lan_futures(device)
                    return

        _LOGGER.warning(
            "datagram_received: didn't find device for %r from %s %r",
            data,
            addr,
            state,
        )

    def _lan_poller_process_broadcast(self, msg: Dict[str, Any], addr: Tuple[str, int]):
        _LOGGER.debug("_lan_poller_process_broadcast msg=%s from %s", msg, addr)

        msg = msg["msg"]
        data = msg["data"]

        if msg["cmd"] == "scan":
            self._process_lan_scan(data)
            return

        if msg["cmd"] == "devStatus":
            self._process_lan_status(data, addr)
            return

        _LOGGER.warning("unknown msg: %r from %s", msg, addr)

    def _match_devices(self, device: GoveeDevice) -> bool:
        changed = False

        if not device.ble_device and self.ble_devices:
            # See if we can match them up
            for entry in self.ble_devices.values():
                if device.device_id.endswith(entry.device.address):
                    device.ble_device = entry.device
                    changed = True
                    _LOGGER.info(
                        "Associating BLE device %s with %s",
                        entry.device.address,
                        device.device_id,
                    )

        if not device.http_definition and self.http_devices:
            device.http_definition = self.http_devices.get(device.device_id, None)
            if device.http_definition is not None:
                changed = True

        return changed

    def _fire_device_change(self, device: GoveeDevice):
        if self.on_device_changed:
            self.on_device_changed(device)

    async def async_stop(self):
        """You must call this when you are done using the controller!
        It will stop the HTTP and LAN listeners"""

        for entry in self.ble_devices.values():
            await entry.disconnect()

        self._stop_common()

    def _stop_common(self):
        if self.http_poller:
            self.http_poller.cancel()
            self.http_poller = None
        if self.ble_poller:
            self.ble_poller.cancel()
            self.ble_poller = None
        if self.ble_idler:
            self.ble_idler.cancel()
            self.ble_idler = None
        for task in self.lan_pollers:
            task.cancel()
        self.lan_pollers = []

    def stop(self):
        """You must call this when you are done using the controller!
        It will stop the HTTP and LAN listeners"""

        entries = []
        for entry in self.ble_devices.values():
            if entry.client:
                entries.append(entry)

        if entries:

            async def close_ble_clients():
                for entry in entries:
                    await entry.disconnect()

            asyncio.create_task(close_ble_clients())

        self._stop_common()


class GoveeLanListener(asyncio.DatagramProtocol):
    """Listens for responses from Govee devices that support
    the LAN protocol"""

    transport = None

    def __init__(self, controller: GoveeController):
        self.controller = controller

    def connection_lost(self, exc):
        pass

    def connection_made(self, transport):
        self.transport = transport

    # pylint: disable=protected-access
    def datagram_received(self, data, addr):
        message = data.decode()
        msg = json.loads(message)
        self.controller._lan_poller_process_broadcast(msg, addr)
