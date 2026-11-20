from typing import Dict, Any, Optional
import time
from .base import BaseConnector

class MockConnector(BaseConnector):
    """
    High-fidelity mock connector for lab testing, automated CI pipelines, and developer environments.
    Provides deterministic vendor responses without requiring physical hardware.
    """
    def __init__(self, host: str = "127.0.0.1", port: int = 22, vendor: str = "mikrotik", timeout: int = 5):
        super().__init__(host, port, timeout)
        self.vendor = vendor.lower()
        self.command_history = []
        self._custom_responses = {}

    def set_response(self, command: str, response: str):
        self._custom_responses[command.strip()] = response

    def connect(self, credentials: Dict[str, Any]) -> bool:
        if credentials.get("username") == "invalid":
            self.is_connected = False
            raise ConnectionError("Mock authentication rejected for user 'invalid'.")
        self.is_connected = True
        return True

    def disconnect(self):
        self.is_connected = False

    def execute_command(self, command: str) -> str:
        if not self.is_connected:
            raise RuntimeError("Mock connector is not connected.")
        
        cmd = command.strip()
        normalized_cmd = " ".join(cmd.replace("/", " ").split()).casefold()
        command_tokens = set(normalized_cmd.split())
        self.command_history.append(cmd)

        if cmd in self._custom_responses:
            return self._custom_responses[cmd]

        # MikroTik default responses
        if "mikrotik" in self.vendor:
            if "system resource print" in normalized_cmd:
                return "uptime: 4w2d18h\nversion: 7.15.2 (stable)\ncpu-load: 12%\nfree-memory: 218.4MiB\ntotal-memory: 256.0MiB"
            elif "interface print" in normalized_cmd:
                return "Flags: D - dynamic, X - disabled, R - running, S - slave\n #    NAME            TYPE       ACTUAL-MTU\n 0 R  ether1          ether            1500\n 1 RS ether2          ether            1500\n 2 RS ether3          ether            1500\n 3 RS ether4          ether            1500\n 4 RS ether5          ether            1500"
            elif "ip address print" in normalized_cmd:
                return "Flags: D - DYNAMIC\nColumns: ADDRESS, NETWORK, INTERFACE\n#   ADDRESS          NETWORK        INTERFACE\n0   10.10.10.1/24    10.10.10.0     bridge1  \n1 D 192.168.1.50/24  192.168.1.0    ether1"
            elif "ppp active print" in normalized_cmd:
                return "Flags: R - radius\n #   NAME         SERVICE CALLER-ID         ADDRESS         UPTIME\n 0 R cust_user101 pppoe   00:15:5D:01:02:03 100.64.10.15    3d12h"
            elif "ping" in command_tokens:
                return "  SEQ HOST                                     SIZE TTL TIME       STATUS\n    0 8.8.8.8                                    56  58 14ms715us\n    1 8.8.8.8                                    56  58 14ms412us\n    sent=2 received=2 packet-loss=0% min-rtt=14ms avg-rtt=14ms"
            elif "add" in command_tokens or "set" in command_tokens:
                return ""  # RouterOS typically returns nothing on successful add/set

        # Cisco IOS default responses
        elif "cisco" in self.vendor:
            if "show version" in cmd:
                return "Cisco IOS XE Software, Version 17.06.05\nCisco C8300-1N1S-4T2X uptime is 12 weeks, 4 days\nSystem image file is 'bootflash:c8300-universalk9.17.06.05.SPA.bin'"
            elif "show ip interface brief" in cmd:
                return "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0/0   192.168.1.1     YES NVRAM  up                    up      \nGigabitEthernet0/0/1   10.200.1.1      YES manual up                    up      \nLoopback0              1.1.1.1         YES manual up                    up"
            elif "ping" in cmd:
                return "Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to 8.8.8.8, timeout is 2 seconds:\n!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 12/14/18 ms"

        # Huawei default responses
        elif "huawei" in self.vendor:
            if "display version" in cmd:
                return "Huawei Versatile Routing Platform Software\nVRP (R) software, Version 5.170 (V200R019C00SPC500)\nQuidway S5720-28P-SI-AC uptime is 32 days"
            elif "display interface brief" in cmd:
                return "PHY: Physical\n*down: administratively down\n(l): loopback\nInterface                   PHY      Protocol Description\nGigabitEthernet0/0/1        up       up       Uplink-Core\nGigabitEthernet0/0/2        up       up       Access-SW02"

        return f"[MOCK {self.vendor.upper()}] Command '{cmd}' executed successfully."

    def ping_check(self) -> bool:
        return self.is_connected
