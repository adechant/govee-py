from awscrt import mqtt
from awsiot import mqtt_connection_builder
from base64 import standard_b64decode
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_pkcs12,
    PKCS12KeyAndCertificates,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
)
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import ssl
from typing import Any, Dict, List

import aiohttp
import certifi
import time
import uuid


_CA_BYTES_BASE64 = """
MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF
ADA5MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRkwFwYDVQQDExBBbWF6
b24gUm9vdCBDQSAxMB4XDTE1MDUyNjAwMDAwMFoXDTM4MDExNzAwMDAwMFowOTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEZMBcGA1UEAxMQQW1hem9uIFJv
b3QgQ0EgMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALJ4gHHKeNXj
ca9HgFB0fW7Y14h29Jlo91ghYPl0hAEvrAIthtOgQ3pOsqTQNroBvo3bSMgHFzZM
9O6II8c+6zf1tRn4SWiw3te5djgdYZ6k/oI2peVKVuRF4fn9tBb6dNqcmzU5L/qw
IFAGbHrQgLKm+a/sRxmPUDgH3KKHOVj4utWp+UhnMJbulHheb4mjUcAwhmahRWa6
VOujw5H5SNz/0egwLX0tdHA114gk957EWW67c4cX8jJGKLhD+rcdqsq08p8kDi1L
93FcXmn/6pUCyziKrlA4b9v7LWIbxcceVOF34GfID5yHI9Y/QCB/IIDEgEw+OyQm
jgSubJrIqg0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0OBBYEFIQYzIU07LwMlJQuCFmcx7IQTgoIMA0GCSqGSIb3DQEBCwUA
A4IBAQCY8jdaQZChGsV2USggNiMOruYou6r4lK5IpDB/G/wkjUu0yKGX9rbxenDI
U5PMCCjjmCXPI6T53iHTfIUJrU6adTrCC2qJeHZERxhlbI1Bjjt/msv0tadQ1wUs
N+gDS63pYaACbvXy8MWy7Vu33PqUXHeeE6V/Uq2V8viTO96LXFvKWlJbYK8U90vv
o/ufQJVtMVT8QtPHRh8jrdkPSHCa2XV4cdFyQzR1bldZwgJcJmApzyMZFo6IQ6XU
5MsI+yMRQ+hDKXJioaldXgjUkK642M4UwtBV8ob2xJNDd2ZhwLnoQdeXeGADbkpy
rqXRfboQnoZsG4q5WTP468SQvvG5"""

_LOGGER = logging.getLogger(__name__)

APP_VERSION = "5.6.01"
USER_AGENT = (
    "GoveeHome/"
    + APP_VERSION
    + " (com.ihoment.GoVeeSensor; build:2; iOS 16.5.0) Alamofire/5.6.4"
)


@dataclass
class GoveeAWSSceneDefinition:
    """Scene information, available via AWS API"""

    # store the name of the scene
    scene: str
    lanCode: str
    bleCode: str


@dataclass
class GoveeAWSDefinition:
    """Device information, available via AWS API"""

    account_id: str
    endpoint: str
    iot: str
    iot_password: str
    token: str
    ttr_token: str
    topic: str

    def complete(self) -> bool:
        comp = True
        comp = comp and (self.account_id is not None)
        comp = comp and (self.endpoint is not None)
        comp = comp and (self.iot is not None)
        comp = comp and (self.iot_password is not None)
        comp = comp and (self.ttr_token is not None)
        comp = comp and (self.topic is not None)
        return comp


class GoveeAWSListener:
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.definition = GoveeAWSDefinition(None, None, None, None, None, None, None)
        # Create a client id generated from Govee email which should remain constant
        clientSuffix = uuid.uuid5(uuid.NAMESPACE_X500, self.email).hex  # 32 chars
        clientSuffix = clientSuffix[:-2]  # 30 chars
        self.client_id = "hb" + clientSuffix  # 32 chars

    async def login(self) -> GoveeAWSDefinition:
        if self.email is None or self.password is None:
            raise RuntimeError(
                f"email and password must be defined before calling login"
            )
        try:
            await self._login_token()
            await self._login_ttr_token()
            await self._login_iot()
            return self.definition
        except Exception as err:
            _LOGGER.info("AWS login failed -> %s", err)
        return None

    async def _login_ttr_token(self) -> bool:
        """Sends a control request"""
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        message = "Failed for an unknown reason"
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(
                url="https://community-api.govee.com/os/v1/login",
                json={
                    "email": self.email,
                    "password": self.password,
                },
            ) as response:
                _LOGGER.debug(
                    "AWS login ttr token request %s -> %s", self.email, response
                )
                if response.status == 200:
                    data = await response.json()
                    _LOGGER.debug("AWS login ttr token request data-> %s", data)
                    try:
                        self.definition.ttr_token = data["data"]["token"]
                        _LOGGER.info(
                            "AWS login ttr token received -> %s",
                            self.definition.ttr_token,
                        )
                    except Exception as err:
                        raise RuntimeError(f"failed to get aws ttr token: {err}")
                    return True
                message = await self._extract_failure_message(response)
        raise RuntimeError(f"failed to get api login token: {message}")

    async def _login_token(self) -> bool:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(
                url="https://app2.govee.com/account/rest/account/v1/login",
                json={
                    "email": self.email,
                    "password": self.password,
                    "client": self.client_id,
                },
            ) as response:
                _LOGGER.debug("AWS login token request %s -> %s", self.email, response)
                if response.status == 200:
                    data = await response.json()
                    _LOGGER.debug("AWS login token request data -> %s", data)
                    try:
                        self.definition.token = data["client"]["token"]
                        self.definition.topic = data["client"]["topic"]
                        self.definition.account_id = data["client"]["accountId"]
                        _LOGGER.info(
                            "AWS login token received -> %s",
                            self.definition.token,
                        )
                        _LOGGER.info(
                            "AWS login topic received -> %s",
                            self.definition.topic,
                        )
                    except Exception as err:
                        raise RuntimeError(f"failed to get aws token: {err}")
                    return True
                message = await self._extract_failure_message(response)
        raise RuntimeError(f"failed to login: {message}")

    async def _login_iot(self) -> bool:
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.get(
                url="https://app2.govee.com/app/v1/account/iot/key",
                headers={
                    "Authorization": "Bearer " + self.definition.token,
                    "appVersion": APP_VERSION,
                    "clientId": self.client_id,
                    "clientType": "1",
                    "iotVersion": "0",
                    "timestamp": str(time.time() * 1000),
                    "User-Agent": USER_AGENT,
                },
            ) as response:
                _LOGGER.debug("AWS login iot request -> %s", response)
                if response.status == 200:
                    data = await response.json()
                    _LOGGER.debug("AWS login iot request data -> %s", data)
                    try:
                        self.definition.endpoint = data["data"]["endpoint"]
                        self.definition.iot = data["data"]["p12"]
                        self.definition.iot_password = data["data"]["p12Pass"]
                        _LOGGER.info(
                            "AWS login iot p12 received -> %s",
                            self.definition.iot,
                        )
                        _LOGGER.info(
                            "AWS login iot p12 password -> %s",
                            self.definition.iot_password,
                        )
                    except Exception as err:
                        raise RuntimeError(f"failed to get aws iot information: {err}")
                    return True
                message = await self._extract_failure_message(response)
        raise RuntimeError(f"failed to login: {message}")

    async def logout(self):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(
                url="https://app2.govee.com/account/rest/account/v1/logout",
                headers={
                    "Authorization": "Bearer " + self.definition.token,
                    "appVersion": APP_VERSION,
                    "clientId": self.client_id,
                    "clientType": "1",
                    "iotVersion": "0",
                    "timestamp": str(time.time() * 1000),
                    "User-Agent": USER_AGENT,
                },
            ) as response:
                _LOGGER.debug("aws logout request -> %s", response)
                if response.status == 200:
                    _LOGGER.info("AWS logout successful")
                    return
                message = await self._extract_failure_message(response)
        raise RuntimeError(f"failed to logout: {message}")

    # not actually used as we assume all HTTP devices can use AWS platform
    async def get_devices(self):
        ssl_context = ssl.create_default_context(cafile=certifi.where())
        conn = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=conn) as session:
            async with session.post(
                url="https://app2.govee.com/device/rest/devices/v1/list",
                headers={
                    "Authorization": "Bearer " + self.definition.token,
                    "appVersion": APP_VERSION,
                    "clientId": self.client_id,
                    "clientType": "1",
                    "iotVersion": "0",
                    "timestamp": str(time.time() * 1000),
                    "User-Agent": USER_AGENT,
                },
            ) as response:
                _LOGGER.debug("aws get devices request -> %s", response)
                if response.status == 200:
                    try:
                        pass
                    except Exception as err:
                        raise RuntimeError(f"failed to get aws iot information: {err}")
                    return True
                message = await self._extract_failure_message(response)
        raise RuntimeError(f"failed to logout: {message}")

    # Callback when connection is accidentally lost.
    def on_connection_interrupted(self, connection, error, **kwargs):
        _LOGGER.debug("Connection interrupted. error: %s".format(error))

    # Callback when an interrupted connection is re-established.
    def on_connection_resumed(self, connection, return_code, session_present, **kwargs):
        _LOGGER.debug(
            "Connection resumed. return_code: {} session_present: {}".format(
                return_code, session_present
            )
        )

        if return_code == mqtt.ConnectReturnCode.ACCEPTED and not session_present:
            _LOGGER.debug("Session did not persist. Resubscribing to existing topics")
            resubscribe_future, _ = connection.resubscribe_existing_topics()

            # Cannot synchronously wait for resubscribe result because we're on the connection's event-loop thread,
            # evaluate result with a callback instead.
            resubscribe_future.add_done_callback(self.on_resubscribe_complete)

    def on_resubscribe_complete(self, resubscribe_future):
        resubscribe_results = resubscribe_future.result()
        _LOGGER.debug("Resubscribe results: {}".format(resubscribe_results))

        for topic, qos in resubscribe_results["topics"]:
            if qos is None:
                _LOGGER.debug("Server rejected resubscribe to topic: {}".format(topic))

    # Callback when the subscribed topic receives a message
    def on_message_received(self, topic, payload, dup, qos, retain, **kwargs):
        _LOGGER.debug("Received message from topic '{}': {}".format(topic, payload))

    # Callback when the connection successfully connects
    def on_connection_success(self, connection, callback_data):
        assert isinstance(callback_data, mqtt.OnConnectionSuccessData)
        _LOGGER.debug(
            "Connection Successful with return code: {} session present: {}".format(
                callback_data.return_code, callback_data.session_present
            )
        )

    # Callback when a connection attempt fails
    def on_connection_failure(self, connection, callback_data):
        assert isinstance(callback_data, mqtt.OnConnectionFailureData)
        _LOGGER.debug(
            "Connection failed with error code: {}".format(callback_data.error)
        )

    # Callback when a connection has been disconnected or shutdown successfully
    def on_connection_closed(self, connection, callback_data):
        _LOGGER.debug("Connection closed")

    async def connect(self):
        if not self.definition.complete():
            raise RuntimeError(f"aws definition is not complete, cannot connect")
        # decode the pkcs12 cert and private key
        # they have been passed from AWS as IOT json data in base64 format
        pycaP12 = load_pkcs12(
            standard_b64decode(self.definition.iot),
            bytes(self.definition.iot_password, "utf-8"),
        )
        cert_bytes = pycaP12.cert.certificate.public_bytes(Encoding.PEM)
        private_key_bytes = pycaP12.key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        ca_bytes = standard_b64decode(_CA_BYTES_BASE64.strip())
        clientID = "AP/" + str(self.definition.account_id) + "/" + self.client_id
        mqtt_connection = mqtt_connection_builder.mtls_from_bytes(
            endpoint=self.definition.endpoint,
            pri_key_bytes=private_key_bytes,
            cert_bytes=cert_bytes,
            # ca_bytes=ca_bytes,
            ca_filepath="/workspaces/ha_core/config/deps/govee-py/govee_led_wez/cert/AmazonRootCA1.pem",
            on_connection_interrupted=self.on_connection_interrupted,
            on_connection_resumed=self.on_connection_resumed,
            client_id=clientID,
            clean_session=False,
            keep_alive_secs=30,
            enable_metrics_collection=False,
            on_connection_success=self.on_connection_success,
            on_connection_failure=self.on_connection_failure,
            on_connection_closed=self.on_connection_closed,
        )

        connect_future = mqtt_connection.connect()

        # Future.result() waits until a result is available
        connect_future.result()
        _LOGGER.info("AWS connected!")

        # Subscribe
        _LOGGER.info("Subscribing to topic '{}'...".format(self.definition.topic))
        subscribe_future, packet_id = mqtt_connection.subscribe(
            topic=self.definition.topic,
            qos=mqtt.QoS.AT_LEAST_ONCE,
            callback=self.on_message_received,
        )

        subscribe_result = subscribe_future.result()
        _LOGGER.debug("Subscribed with {}".format(str(subscribe_result["qos"])))

        disconnect_future = mqtt_connection.disconnect()
        disconnect_future.result()
        _LOGGER.info("AWS disonnected!")

    async def _extract_failure_message(self, response) -> str:
        try:
            data = await response.json()
            if "message" in data:
                return data["message"]
        except Exception:  # pylint: disable=broad-except
            pass
        return await response.text()


async def aws_get_supported_scenes(self) -> List[GoveeAWSSceneDefinition]:
    sceneList = []

    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://app2.govee.com/bff-app/v1/exec-plat/home",
            headers={
                "Authorization": "Bearer " + self.definition.token,
                "appVersion": APP_VERSION,
                "clientId": self.client_id,
                "clientType": "1",
                "iotVersion": "0",
                "timestamp": str(time.time() * 1000),
                "User-Agent": USER_AGENT,
            },
        ) as response:
            _LOGGER.debug(
                "AWS get supported scene request %s -> %s",
                self.definition.token,
                response,
            )
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
            message = await self._extract_failure_message(response)
    raise RuntimeError(f"failed to get api login token: {message}")
