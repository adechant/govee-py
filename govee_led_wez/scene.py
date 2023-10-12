from dataclasses import dataclass
from typing import Dict, List


@dataclass
class GoveeScene:
    """Represents a scene defined in the Govee App"""

    # scene codes delivered by LAN or by API are arrays of base64 strings
    __scenesLAN = {
        "sunrise": [
            "owABCwcJAGQAAAAIDIsA/0hJSvg=",
            "owFLTE1OT1BRUlMMABKJbG1ub34=",
            "owJwcXJzdHV2dwz/GfRgYWJjZNs=",
            "owNlZmdoaWprDN400lRVVldYWfE=",
            "owRaW1xdXl8Y/wAAAAECAwQFBkY=",
            "owUHCAkKCwwNDg8QERITFBUWF6E=",
            "owYY/38AGBkaGxwdHh8gISIjJBk=",
            "owclJicoKSorLC0uLxj//wAwMZk=",
            "owgyMzQ1Njc4OTo7PD0+P0BBQuk=",
            "owlDREVGRwwAAP94eXp7fH1+fxo=",
            "o/+AgYKDAAAAAAAAAAAAAAAAAFw=",
            "MwUELAEAAAAAAAAAAAAAAAAAAB8=",
        ]
    }

    # scene codes delivered by BLE are byte encoded
    __scenesBLE = {
        "sunrise": [0x33, 0x05, 0x04, 0x00],
        "sunset": [0x33, 0x05, 0x04, 0x01],
        # "":       [0x33,0x05,0x04,0x02],
        # "":       [0x33,0x05,0x04,0x03],
        "movie": [0x33, 0x05, 0x04, 0x04],
        "dating": [0x33, 0x05, 0x04, 0x05],
        # "":       [0x33,0x05,0x04,0x06],
        "romantic": [0x33, 0x05, 0x04, 0x07],
        "blinking": [0x33, 0x05, 0x04, 0x08],
        "candlelight": [0x33, 0x05, 0x04, 0x09],
        # "":       [0x33,0x05,0x04,0x0a],
        # "":       [0x33,0x05,0x04,0x0b],
        # "":       [0x33,0x05,0x04,0x0c],
        # "":       [0x33,0x05,0x04,0x0d],
        # "":       [0x33,0x05,0x04,0x0e],
        "snowflake": [0x33, 0x05, 0x04, 0x0F],
    }

    __music = {
        "energic": "33 05 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 37",
        "spectrum": "3305010100RRGGBB0000000000000000000000c9",
        "rolling": "3305010200RRGGBB0000000000000000000000ca",
        "rhythm": "3305010300000000000000000000000000000034",
    }

    @staticmethod
    def scenes() -> List[str]:
        ret_list = GoveeScene.__scenesBLE.keys()
        return list(ret_list)

    # store the name of the scene
    scene: str = None

    def as_string(self) -> str:
        """Returns name as str"""
        return self.scene

    def as_hex_code(self) -> str:
        """Returns scene as hex code"""
        return GoveeScene.__scenesLAN.get(self.scene)

    def as_byte_array(self) -> List[int]:
        return GoveeScene.__scenesBLE.get(self.scene)

    @staticmethod
    def from_name(name: str):
        """Tries to find the scene name in the scenes dictionary, returning "surnrise scene" as default"""
        if GoveeScene.__scenes.get(name, None) is None:
            name = "sunrise"
        return GoveeScene(scene=name)
