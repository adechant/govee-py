from dataclasses import dataclass
from enum import Enum
from typing import Dict


class BleColorMode(Enum):
    """The packet format for updating colors"""

    MODE_2 = 1
    MODE_D = 2
    MODE_1501 = 3


class HttpSceneMode(Enum):
    MODE_REAL = 1
    MODE_OP = 2


@dataclass
class ModelInfo:
    """Describes what we know about a given device model"""

    ble_color_mode: BleColorMode = BleColorMode.MODE_2
    ble_brightness_max: int = 255
    http_scene_mode: HttpSceneMode = HttpSceneMode.MODE_REAL

    @staticmethod
    def resolve(model: str):
        """Lookup model and returns its info. If no info is found,
        assume a reasonable default, which may not be accurate"""
        if info := INFO_BY_MODEL.get(model, None):
            return info
        return ModelInfo()


INFO_BY_MODEL: Dict[str, ModelInfo] = {
    "H6110": ModelInfo(
        BleColorMode.MODE_2,
        ble_brightness_max=255,
        http_scene_mode=HttpSceneMode.MODE_OP,
    ),
    "H613B": ModelInfo(
        BleColorMode.MODE_D,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
    "H613D": ModelInfo(
        BleColorMode.MODE_D,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
    "H617E": ModelInfo(
        BleColorMode.MODE_D,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
    "H6102": ModelInfo(
        BleColorMode.MODE_1501,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
    "H6072": ModelInfo(
        BleColorMode.MODE_1501,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
    "H6058": ModelInfo(
        BleColorMode.MODE_D,
        ble_brightness_max=100,
        http_scene_mode=HttpSceneMode.MODE_REAL,
    ),
}
