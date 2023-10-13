from dataclasses import dataclass
import json
import logging
import ssl
from typing import Any, Dict, List

import aiohttp
import certifi
import time
import uuid

_LOGGER = logging.getLogger(__name__)

APP_VERSION = "5.6.01"
USER_AGENT = (
    "GoveeHome/"
    + APP_VERSION
    + " (com.ihoment.GoVeeSensor; build:2; iOS 16.5.0) Alamofire/5.6.4"
)


@dataclass
class GoveeHttpSceneDefinition:
    """Scene information, available via HTTP API"""

    # store the name of the scene
    scene: str
    lanCode: str
    bleCode: str


@dataclass
class GoveeHttpDeviceDefinition:
    """Device information, available via HTTP API"""

    device_id: str
    model: str
    device_name: str
    controllable: bool
    retrievable: bool
    supported_commands: List[str]
    properties: Dict[str, Any]


async def _extract_failure_message(response) -> str:
    try:
        data = await response.json()
        if "message" in data:
            return data["message"]
    except Exception:  # pylint: disable=broad-except
        pass
    return await response.text()


async def http_get_devices(api_key: str) -> List[GoveeHttpDeviceDefinition]:
    """Requests the list of devices via the HTTP API"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://developer-api.govee.com/v1/devices",
            headers={"Govee-API-Key": api_key},
        ) as response:
            if response.status == 200:
                data = await response.json()
                if (
                    ("data" in data)
                    and ("devices" in data["data"])
                    and isinstance(data["data"]["devices"], list)
                ):
                    return [
                        GoveeHttpDeviceDefinition(
                            device_id=d["device"],
                            model=d["model"],
                            device_name=d["deviceName"],
                            controllable=d["controllable"],
                            retrievable=d["retrievable"],
                            supported_commands=d["supportCmds"],
                            properties=d.get("properties", {}),
                        )
                        for d in data["data"]["devices"]
                    ]

            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get devices: {message}")


async def http_get_state(api_key: str, device_id: str, model: str) -> List[Any]:
    """Requests a list of properties representing the state of the specified device"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://developer-api.govee.com/v1/devices/state",
            headers={"Govee-API-Key": api_key},
            params={"model": model, "device": device_id},
        ) as response:
            if response.status == 200:
                data = await response.json()
                if "data" in data and "properties" in data["data"]:
                    return data["data"]["properties"]

            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get device state: {message}")


async def http_device_control(api_key: str, params: Dict[str, Any]):
    """Sends a control request"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.put(
            url="https://developer-api.govee.com/v1/devices/control",
            headers={"Govee-API-Key": api_key},
            json=params,
        ) as response:
            _LOGGER.debug("http control request %s -> %s", params, response)
            if response.status == 200:
                resp = await response.json()
                return resp
            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to control device: {message}")


async def http_login_token(username: str, password: str) -> str:
    """Sends a control request"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.post(
            url="https://community-api.govee.com/os/v1/login",
            json={
                "email": username,
                "password": password,
            },
        ) as response:
            _LOGGER.debug("http login token request %s -> %s", username, response)
            if response.status == 200:
                data = await response.json()
                if (
                    ("data" in data)
                    and ("token" in data["data"])
                    and isinstance(data["data"]["token"], str)
                ):
                    return data["data"]["token"]
            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get api login token: {message}")


async def http_get_supported_scenes(
    username: str, token: str
) -> List[GoveeHttpSceneDefinition]:
    sceneList = []
    # Create a client id generated from Govee username which should remain constant
    clientSuffix = uuid.uuid5(uuid.NAMESPACE_X500, username).hex  # 32 chars
    clientSuffix = clientSuffix[:-2]  # 30 chars
    clientId = "hb" + clientSuffix  # 32 chars

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://app2.govee.com/bff-app/v1/exec-plat/home",
            headers={
                "Authorization": "Bearer " + token,
                "appVersion": APP_VERSION,
                "clientId": clientId,
                "clientType": "1",
                "iotVersion": "0",
                "timestamp": str(time.time() * 1000),
                "User-Agent": USER_AGENT,
            },
        ) as response:
            _LOGGER.debug("http get supported scene request %s -> %s", token, response)
            if response.status == 200:
                data = await response.json()
                if (
                    ("data" in data)
                    and ("components" in data["data"])
                    and isinstance(data["data"]["components"], list)
                ):
                    # print(json.dumps(data,indent=4,sort_keys=True,))
                    components = data["data"]["components"]
                    for component in components:
                        if "oneClicks" in component.keys():
                            oneClicks = component["oneClicks"]
                            for oneClick in oneClicks:
                                if "iotRules" in oneClick.keys():
                                    iotRules = oneClick["iotRules"]
                                    for iotRule in iotRules:
                                        if (
                                            "deviceObj" in iotRule.keys()
                                            and "rule" in iotRule.keys()
                                        ):
                                            deviceObj = iotRule["deviceObj"]
                                            rule_name = "unknown_rule"
                                            if "name" in deviceObj.keys():
                                                rule_name = deviceObj["name"]
                                            ttr_name = "unkonwn_ttr"
                                            if "name" in oneClick.keys():
                                                ttr_name = oneClick["name"]
                                            rules = iotRule["rule"]
                                            for rule in rules:
                                                _LOGGER.debug(
                                                    "%s %s ttr rule debug: %s",
                                                    rule_name,
                                                    ttr_name,
                                                    rule,
                                                )
                                                if "iotMsg" in rule.keys():
                                                    iotMsg = rule["iotMsg"]
                                                    if len(iotMsg) > 0:
                                                        iotMsg = json.loads(
                                                            rule["iotMsg"]
                                                        )
                                                        if "msg" in iotMsg.keys():
                                                            msg = iotMsg["msg"]
                                                            if "cmd" in msg.keys():
                                                                cmd = msg["cmd"]
                                                                command = None
                                                                if cmd == "ptReal":
                                                                    command = msg[
                                                                        "data"
                                                                    ]["command"]
                                                                elif cmd == "pt":
                                                                    command = msg[
                                                                        "data"
                                                                    ]["value"]
                                                                if command is not None:
                                                                    _LOGGER.info(
                                                                        "[%s] [%s] [HTTP] %s",
                                                                        rule_name,
                                                                        ttr_name,
                                                                        str.join(
                                                                            ",",
                                                                            command,
                                                                        ),
                                                                    )
                                                                    # TODO ADD TO SCENE LIST SOMEWHERE!!!
                                                    if "blueMsg" in rule.keys():
                                                        blueMsg = rule["blueMsg"]
                                                        if len(blueMsg) > 0:
                                                            blueMsg = json.loads(
                                                                blueMsg
                                                            )
                                                            if (
                                                                "type" in blueMsg.keys()
                                                                and "bleCmd"
                                                                in blueMsg.keys()
                                                            ):
                                                                mType = blueMsg["type"]
                                                                if mType == "scene":
                                                                    command = blueMsg[
                                                                        "bleCmd"
                                                                    ]
                                                                    _LOGGER.info(
                                                                        "[%s] [%s] [BLE] %s",
                                                                        rule_name,
                                                                        ttr_name,
                                                                        command,
                                                                    )
                                                                    # TODO ADD TO SCENE LIST SOMEWHERE!!!
                return sceneList
            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get api login token: {message}")
