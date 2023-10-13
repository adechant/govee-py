from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class GoveeScene:
    """Represents a scene defined in the Govee App"""

    # store the name of the scene
    name: str
    lanCode: str
    bleCode: List[int]


@dataclass
class GoveeSceneList:
    __scenes = {
        "sunrise": GoveeScene(
            "sunrise", "MwUEAAAAAAAAAAAAAAAAAAAAADI=", [0x33, 0x05, 0x04, 0x00]
        ),
        "sunset": GoveeScene(
            "sunset", "MwUEAQAAAAAAAAAAAAAAAAAAADM=", [0x33, 0x05, 0x04, 0x01]
        ),
        "dusk": GoveeScene(
            "dusk", "MwUEewAAAAAAAAAAAAAAAAAAAEk=", [0x33, 0x05, 0x04, 0x7B]
        ),
        "sunset glow": GoveeScene(
            "sunset glow", "MwUEfAAAAAAAAAAAAAAAAAAAAE4=", [0x33, 0x05, 0x04, 0x7C]
        ),
        "lightning": GoveeScene(
            "lightning", "MwUEZwAAAAAAAAAAAAAAAAAAAFU=", [0x33, 0x05, 0x04, 0x67]
        ),
        "starry sky": GoveeScene(
            "starry sky", "MwUEagAAAAAAAAAAAAAAAAAAAFg=", [0x33, 0x05, 0x04, 0x6A]
        ),
        "universe": GoveeScene(
            "universe", "MwUEdAAAAAAAAAAAAAAAAAAAAEY=", [0x33, 0x05, 0x04, 0x74]
        ),
        "aurora": GoveeScene(
            "aurora", "MwUEdAAAAAAAAAAAAAAAAAAAAEY=", [0x33, 0x05, 0x04, 0x68]
        ),
        "rainbow": GoveeScene(
            "rainbow", "MwUEdQAAAAAAAAAAAAAAAAAAAEc=", [0x33, 0x05, 0x04, 0x75]
        ),
        "sky": GoveeScene(
            "sky", "MwUEdgAAAAAAAAAAAAAAAAAAAEQ=", [0x33, 0x05, 0x04, 0x76]
        ),
        "fire": GoveeScene(
            "fire", "MwUEaQAAAAAAAAAAAAAAAAAAAFs=", [0x33, 0x05, 0x04, 0x69]
        ),
        "forest": GoveeScene(
            "forest", "MwUEZAAAAAAAAAAAAAAAAAAAAFY=", [0x33, 0x05, 0x04, 0x64]
        ),
        "surge": GoveeScene(
            "surge", "MwUEnQAAAAAAAAAAAAAAAAAAAK8=", [0x33, 0x05, 0x04, 0x9D]
        ),
        "river": GoveeScene(
            "river", "MwUEeQAAAAAAAAAAAAAAAAAAAEs=", [0x33, 0x05, 0x04, 0x79]
        ),
        "clear lake": GoveeScene(
            "clear lake", "MwUEeAAAAAAAAAAAAAAAAAAAAEo=", [0x33, 0x05, 0x04, 0x78]
        ),
        "grassland": GoveeScene(
            "grassland", "MwUEdwAAAAAAAAAAAAAAAAAAAEU=", [0x33, 0x05, 0x04, 0x77]
        ),
        "desert": GoveeScene(
            "desert", "MwUEegAAAAAAAAAAAAAAAAAAAEg=", [0x33, 0x05, 0x04, 0x7A]
        ),
        "spring": GoveeScene(
            "spring", "MwUEfQAAAAAAAAAAAAAAAAAAAE8=", [0x33, 0x05, 0x04, 0x7D]
        ),
        "summer": GoveeScene(
            "summer", "MwUEfgAAAAAAAAAAAAAAAAAAAEw=", [0x33, 0x05, 0x04, 0x7E]
        ),
        "fall": GoveeScene(
            "fall", "MwUEgAAAAAAAAAAAAAAAAAAAALI=", [0x33, 0x05, 0x04, 0x80]
        ),
        "winter": GoveeScene(
            "winter", "MwUEfwAAAAAAAAAAAAAAAAAAAE0=", [0x33, 0x05, 0x04, 0x7F]
        ),
        "party": GoveeScene(
            "party", "MwUElwAAAAAAAAAAAAAAAAAAAKU=", [0x33, 0x05, 0x04, 0x97]
        ),
        "candlelight": GoveeScene(
            "candlelight", "MwUECQAAAAAAAAAAAAAAAAAAADs=", [0x33, 0x05, 0x04, 0x09]
        ),
        "christmas": GoveeScene(
            "christmas", "MwUEbQAAAAAAAAAAAAAAAAAAAF8=", [0x33, 0x05, 0x04, 0x6D]
        ),
        "halloween": GoveeScene(
            "halloween", "MwUE9wMAAAAAAAAAAAAAAAAAAMY=", [0x33, 0x05, 0x04, 0xF7, 0x03]
        ),
        "ghost": GoveeScene(
            "ghost", "MwUEpAAAAAAAAAAAAAAAAAAAAJY=", [0x33, 0x05, 0x04, 0xA4]
        ),
        "valentine's day": GoveeScene(
            "valentine's day", "MwUEmQAAAAAAAAAAAAAAAAAAAKs=", [0x33, 0x05, 0x04, 0x99]
        ),
        "mother's day": GoveeScene(
            "mother's day", "MwUEmgAAAAAAAAAAAAAAAAAAAKg=", [0x33, 0x05, 0x04, 0x9A]
        ),
        "father's day": GoveeScene(
            "father's day", "MwUEmwAAAAAAAAAAAAAAAAAAAKk=", [0x33, 0x05, 0x04, 0x9B]
        ),
        "thanksgiving": GoveeScene(
            "thanksgiving", "MwUEnAAAAAAAAAAAAAAAAAAAAK4=", [0x33, 0x05, 0x04, 0x9C]
        ),
        "dance party": GoveeScene(
            "dance party", "MwUEngAAAAAAAAAAAAAAAAAAAKw=", [0x33, 0x05, 0x04, 0x9E]
        ),
        "disco": GoveeScene(
            "disco", "MwUEhAAAAAAAAAAAAAAAAAAAALY=", [0x33, 0x05, 0x04, 0x84]
        ),
        "sweet": GoveeScene(
            "sweet", "MwUEawAAAAAAAAAAAAAAAAAAAFk=", [0x33, 0x05, 0x04, 0x6B]
        ),
        "dating": GoveeScene(
            "dating", "MwUEBQAAAAAAAAAAAAAAAAAAADc=", [0x33, 0x05, 0x04, 0x05]
        ),
        "romantic": GoveeScene(
            "romantic", "MwUEBwAAAAAAAAAAAAAAAAAAADU=", [0x33, 0x05, 0x04, 0x07]
        ),
        "twinkle": GoveeScene(
            "twinkle", "MwUECAAAAAAAAAAAAAAAAAAAADo=", [0x33, 0x05, 0x04, 0x08]
        ),
        "siren": GoveeScene(
            "siren", "MwUEbAAAAAAAAAAAAAAAAAAAAF4=", [0x33, 0x05, 0x04, 0x6C]
        ),
        "fight": GoveeScene(
            "fight", "MwUEhQAAAAAAAAAAAAAAAAAAALc=", [0x33, 0x05, 0x04, 0x85]
        ),
        "sports": GoveeScene(
            "sports", "MwUEgQAAAAAAAAAAAAAAAAAAALM=", [0x33, 0x05, 0x04, 0x81]
        ),
        "game": GoveeScene(
            "game", "MwUEggAAAAAAAAAAAAAAAAAAALA=", [0x33, 0x05, 0x04, 0x82]
        ),
        "movie": GoveeScene(
            "movie", "MwUEBAAAAAAAAAAAAAAAAAAAADY=", [0x33, 0x05, 0x04, 0x04]
        ),
        "study": GoveeScene(
            "study", "MwUEiQAAAAAAAAAAAAAAAAAAALs=", [0x33, 0x05, 0x04, 0x89]
        ),
        "business": GoveeScene(
            "business", "MwUEigAAAAAAAAAAAAAAAAAAALg=", [0x33, 0x05, 0x04, 0x8A]
        ),
        "work": GoveeScene(
            "work", "MwUEnwAAAAAAAAAAAAAAAAAAAK0=", [0x33, 0x05, 0x04, 0x9F]
        ),
        "reading": GoveeScene(
            "reading", "MwUEoAAAAAAAAAAAAAAAAAAAAJI=", [0x33, 0x05, 0x04, 0xA0]
        ),
        "afternoon": GoveeScene(
            "afternoon", "MwUEhgAAAAAAAAAAAAAAAAAAALQ=", [0x33, 0x05, 0x04, 0x86]
        ),
        "morning": GoveeScene(
            "morning", "MwUEhwAAAAAAAAAAAAAAAAAAALU=", [0x33, 0x05, 0x04, 0x87]
        ),
        "night": GoveeScene(
            "night", "MwUEiAAAAAAAAAAAAAAAAAAAALo=", [0x33, 0x05, 0x04, 0x88]
        ),
        "sleep": GoveeScene(
            "sleep", "MwUEoQAAAAAAAAAAAAAAAAAAAJM=", [0x33, 0x05, 0x04, 0xA1]
        ),
        "night light": GoveeScene(
            "night light", "MwUEogAAAAAAAAAAAAAAAAAAAJA=", [0x33, 0x05, 0x04, 0xA2]
        ),
        "breathe": GoveeScene(
            "breathe", "MwUECgAAAAAAAAAAAAAAAAAAADg=", [0x33, 0x05, 0x04, 0x0A]
        ),
        "energetic": GoveeScene(
            "energetic", "MwUEEAAAAAAAAAAAAAAAAAAAACI=", [0x33, 0x05, 0x04, 0x10]
        ),
        "happy": GoveeScene(
            "happy", "MwUEjAAAAAAAAAAAAAAAAAAAAL4=", [0x33, 0x05, 0x04, 0x8C]
        ),
        "enthusiastic": GoveeScene(
            "enthusiastic", "MwUEjgAAAAAAAAAAAAAAAAAAALw=", [0x33, 0x05, 0x04, 0x8E]
        ),
        "excited": GoveeScene(
            "excited", "MwUElgAAAAAAAAAAAAAAAAAAAKQ=", [0x33, 0x05, 0x04, 0x96]
        ),
        "active": GoveeScene(
            "active", "MwUEkQAAAAAAAAAAAAAAAAAAAKM=", [0x33, 0x05, 0x04, 0x91]
        ),
        "warm": GoveeScene(
            "warm", "MwUEjwAAAAAAAAAAAAAAAAAAAL0=", [0x33, 0x05, 0x04, 0x8F]
        ),
        "quiet": GoveeScene(
            "quiet", "MwUEiwAAAAAAAAAAAAAAAAAAALk=", [0x33, 0x05, 0x04, 0x8B]
        ),
        "profound": GoveeScene(
            "profound", "MwUEowAAAAAAAAAAAAAAAAAAAJE=", [0x33, 0x05, 0x04, 0xA3]
        ),
        "longing": GoveeScene(
            "longing", "MwUEkgAAAAAAAAAAAAAAAAAAAKA=", [0x33, 0x05, 0x04, 0x92]
        ),
        "dreamland": GoveeScene(
            "dreamland", "MwUEkwAAAAAAAAAAAAAAAAAAAKE=", [0x33, 0x05, 0x04, 0x93]
        ),
        "relax": GoveeScene(
            "relax", "MwUElAAAAAAAAAAAAAAAAAAAAKY=", [0x33, 0x05, 0x04, 0x94]
        ),
        "retro": GoveeScene(
            "retro", "MwUElQAAAAAAAAAAAAAAAAAAAKc=", [0x33, 0x05, 0x04, 0x95]
        ),
    }

    @staticmethod
    def scene_names() -> List[str]:
        ret_list = GoveeSceneList.__scenes.keys()
        return list(ret_list)

    @staticmethod
    def from_name(name: str) -> GoveeScene:
        """Tries to find the scene name in the scenes dictionary, returning "surnrise" as default"""
        if name not in GoveeSceneList.__scenes.keys():
            name = "sunrise"
        return GoveeSceneList.__scenes[name]
