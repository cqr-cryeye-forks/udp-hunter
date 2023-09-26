import pathlib
from typing import Final

ROOT_PATH: Final[pathlib.Path] = pathlib.Path(__file__).parent
UDP_HELP_PATH: Final[pathlib.Path] = ROOT_PATH.joinpath("udphelp.txt")
UDP_PATH: Final[pathlib.Path] = ROOT_PATH.joinpath("udp.txt")
