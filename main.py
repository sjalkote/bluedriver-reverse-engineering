import asyncio
import sys
import time

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic

# Important GATT UUIDs

CMD_UUID = "a9da6040-0823-4995-94ec-9ce41ca28833"
DATA_UUID = "a73e9a10-628f-4494-a099-12efaf72258f"
STATUS_UUID = "75a9f022-af03-4e41-b4bc-9de90a47d50b"
PAIR_TRIGGER_UUID = "12e868e7-c926-4906-96c8-a7ee81d4b1b3"
FIRMWARE_UUID = "00002a26-0000-1000-8000-00805f9b34fb"
MODEL_UUID = "00002a24-0000-1000-8000-00805f9b34fb"

SCAN_NAME_PREFIXES = ("BlueDriv", "LSB2-")
XOR_KEY = 0x26

DEBUG = False
_T0 = time.monotonic()  # reference clock for --debug timestamps

# XOR encryption


def xor_codec(data: bytes) -> bytes:
    """XOR every byte with 0x26; 0x0D and 0x3E pass through unchanged."""
    return bytes(b ^ XOR_KEY if b not in (0x0D, 0x3E) else b for b in data)


def make_cmd(text: str) -> bytes:
    if not text.endswith("\r"):
        text += "\r"
    return xor_codec(text.encode("ascii"))


# OBDII value decoding


def decode_pid_value(pid: str, hex_bytes: str) -> str:
    try:
        d = bytes.fromhex(hex_bytes)
        pid = pid.upper()
        if pid == "010C" and len(d) >= 2:
            return f"{((d[0] << 8) | d[1]) / 4:.0f} RPM"
        if pid == "010D":
            return f"{d[0]} km/h"
        if pid == "0105":
            return f"{d[0] - 40} °C"
        if pid == "010F":
            return f"{d[0] - 40} °C"
        if pid == "0104":
            return f"{d[0] * 100 / 255:.1f} %"
        if pid == "0111":
            return f"{d[0] * 100 / 255:.1f} %"
        if pid == "012F":
            return f"{d[0] * 100 / 255:.1f} %"
        if pid == "010B":
            return f"{d[0]} kPa"
        if pid == "0142" and len(d) >= 2:
            return f"{((d[0] << 8) | d[1]) / 1000:.2f} V"
        return hex_bytes
    except Exception:
        return hex_bytes


# Number of DATA bytes each mode-01 PID returns — needed to split a combined
# (multi-PID) response back into individual values.
PID_DATA_LEN = {
    "010C": 2,
    "010D": 1,
    "0105": 1,
    "010F": 1,
    "0104": 1,
    "0111": 1,
    "012F": 1,
    "010B": 1,
    "0142": 2,
}


class BlueDriverClient:
    def __init__(self, address: str):
        self.address = address
        self._client: BleakClient | None = None
        self._rx_buf = bytearray()
        self._rx_event = asyncio.Event()
        self._loop = asyncio.get_event_loop()

    # Connect / Disconnect

    async def connect(self):
        self._client = BleakClient(self.address, timeout=15.0)
        await self._client.connect()
        if not self._client.is_connected:
            raise RuntimeError("connect() returned but is_connected is False")

    async def disconnect(self):
        if self._client and self._client.is_connected:
            await self._client.disconnect()

    # Notification callbacks

    def _on_cmd(self, _: BleakGATTCharacteristic, data: bytearray):
        # 01 01 00 ACKs + occasional 00 FF 07 status. These are ignored.
        if DEBUG:
            print(
                f"\n[{(time.monotonic() - _T0) * 1000:9.1f}ms  CMD <-] {bytes(data).hex()}"
            )

    def _on_data(self, _: BleakGATTCharacteristic, data: bytearray):
        """
        DATA notification fragment.

        Per-fragment credit-based flow control: ACK with 01 <len> 00 IMMEDIATELY.
        bleak's macOS backend dispatches notifications onto the asyncio loop via
        call_soon_threadsafe, so we're already on the loop here — use
        asyncio.create_task (NOT run_coroutine_threadsafe, which is for
        cross-thread scheduling and adds significant overhead).

        Then XOR-decode and append to the response buffer; signal completion
        when '>' (ELM prompt) appears.
        """
        n = len(data)
        if n == 0:
            return

        # Fire-and-forget ACK on the same loop — fast path
        ack = bytes([0x01, n & 0xFF, 0x00])
        try:
            self._loop.create_task(
                self._client.write_gatt_char(DATA_UUID, ack, response=False)
            )
        except Exception as e:
            if DEBUG:
                print(f"\n[ACK error] {e}")

        decoded = xor_codec(bytes(data))
        self._rx_buf.extend(decoded)

        if DEBUG:
            print(
                f"\n[{(time.monotonic() - _T0) * 1000:9.1f}ms  DATA <- {n:2d}B] "
                f"wire={bytes(data).hex()}  dec={decoded!r}"
            )

        if b">" in self._rx_buf:
            # We're already on the loop; just set() directly.
            self._rx_event.set()

    def _on_status(self, _: BleakGATTCharacteristic, data: bytearray):
        if DEBUG:
            print(f"\n[STAT <-] {bytes(data).hex()}")

    # Setup

    async def setup(self):
        c = self._client
        print("  Subscribing to notifications...")
        await c.start_notify(CMD_UUID, self._on_cmd)
        await c.start_notify(DATA_UUID, self._on_data)
        await c.start_notify(STATUS_UUID, self._on_status)

        print("  Triggering BLE pairing (read encrypted characteristic)...")
        try:
            token = await asyncio.wait_for(
                c.read_gatt_char(PAIR_TRIGGER_UUID), timeout=20.0
            )
            print(f"  Paired & encrypted ✓  (token: {token.hex()})")
        except asyncio.TimeoutError:
            raise RuntimeError(
                "Pairing timed out. Make sure no other device is connected\n"
                "to the BlueDriver and the scanner is in a car with ACC on."
            )
        except Exception as e:
            print(f"  Pairing-read warning: {e}  (bond likely cached, continuing)")
            await asyncio.sleep(0.5)

        try:
            fw = await c.read_gatt_char(FIRMWARE_UUID)
            model = await c.read_gatt_char(MODEL_UUID)
            print(f"  Firmware : {fw.decode('ascii', errors='replace').strip()}")
            print(f"  Model    : {model.decode('ascii', errors='replace').strip()}")
        except Exception:
            pass

    # LM Init

    async def lm_init(self):
        """
        Replicate the iOS app's LM init.

        Sent in this order:
            LMI  → "?\\r>"  or  "OSAPI v2.60\\rOK\\r>"
            LMD  → "OK\\r>"
            LML0 → "?\\r>"
            LMI  → "OSAPI v2.60\\rOK\\r>"
            LMD  → "OK\\r>"
            LMDP → "<protocol#>\\rOK\\r>"
            LMI  → "OSAPI v2.60\\rOK\\r>"
            LMX1 → "OK\\r>"
            LMX0 → "OK\\r>"
        """
        # Open the 255-byte receive credit window
        await self._client.write_gatt_char(DATA_UUID, b"\x00\xff\x7f", response=False)
        await asyncio.sleep(0.1)

        lm_sequence = [
            "LMI",
            "LMD",
            "LML0",
            "LMI",
            "LMD",
            "LMDP",
            "LMI",
            "LMX1",
            "LMX0",
        ]
        for cmd in lm_sequence:
            resp = await self._send_recv(cmd, timeout=3.0)
            short = self._clean(resp)
            short_disp = (short[:50] + "…") if len(short) > 50 else short
            print(f"  {cmd:<5} → {short_disp!r}")
            await asyncio.sleep(0.05)

    # Send / Receive

    @staticmethod
    def _clean(s: str) -> str:
        return s.replace(">", "").replace("\r", " ").replace("\n", " ").strip()

    async def _send_recv(self, cmd: str, timeout: float = 3.0) -> str:
        # Clear buffer BEFORE sending, so a stale '>' from a previous response
        # can't satisfy the wait immediately.
        self._rx_buf.clear()
        self._rx_event.clear()

        if DEBUG:
            t0 = time.monotonic()
            print(
                f"\n[{(t0 - _T0) * 1000:9.1f}ms  CMD ->] {cmd!r}  wire={make_cmd(cmd).hex()}"
            )

        await self._client.write_gatt_char(CMD_UUID, make_cmd(cmd), response=False)

        try:
            await asyncio.wait_for(self._rx_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            if DEBUG:
                print(f"[timeout after {timeout}s] buf={bytes(self._rx_buf)!r}")

        if DEBUG:
            print(f"[CMD {cmd!r} round-trip {(time.monotonic() - t0) * 1000:.1f}ms]")

        return self._rx_buf.decode("ascii", errors="replace")

    async def send(self, cmd: str, timeout: float = 4.0) -> str:
        return await self._send_recv(cmd.strip().upper(), timeout=timeout)

    async def send_pid(self, pid: str, timeout: float = 2.5) -> str:
        """
        Send an OBD-II PID and returns the response data bytes as concatenated hex.
        """
        raw = await self._send_recv(pid, timeout=timeout)
        return self._parse_pid_response(pid, raw)

    def _parse_pid_response(self, pid: str, raw: str) -> str:
        """Extract data hex from one PID's response text."""
        cleaned = self._clean(raw)
        if any(
            x in cleaned.upper()
            for x in ("NO DATA", "UNABLE", "ERROR", "STOPPED", "?", "SEARCHING")
        ):
            return ""
        hex_only = "".join(ch for ch in cleaned if ch in "0123456789abcdefABCDEF")
        if len(pid) == 4 and len(hex_only) >= 4:
            try:
                mode = int(pid[:2], 16)
                expected_echo = f"{mode | 0x40:02X}{pid[2:].upper()}"
                if hex_only.upper().startswith(expected_echo):
                    hex_only = hex_only[4:]
            except ValueError:
                pass
        if len(hex_only) % 2 == 1:
            hex_only = hex_only[:-1]
        return hex_only

    async def send_pids_multi(self, pids: list[str]) -> dict[str, str]:
        """
        Request several mode-01 PIDs in a SINGLE OBD message.
        """
        if not pids or len(pids) > 6:
            return {}
        if {p[:2] for p in pids} != {"01"}:
            return {}
        combined = "01" + "".join(p[2:] for p in pids)
        raw = await self._send_recv(combined, timeout=2.0)
        result = self._parse_multi_response(pids, raw)
        if DEBUG:
            print(f"[multi raw resp] {raw!r}")
            print(f"[multi parsed  ] {result}")
        return result

    def _parse_multi_response(self, pids: list[str], raw: str) -> dict[str, str]:
        """
        Walk a combined mode-01 response.
        """
        cleaned = self._clean(raw)
        up = cleaned.upper()
        if any(x in up for x in ("NO DATA", "UNABLE", "ERROR", "STOPPED", "SEARCHING")):
            return {}
        # Drop ELM frame markers ("0:", "1:"); keep hex digits only.
        toks = [t for t in up.split() if not t.endswith(":")]
        hexstr = "".join(ch for ch in "".join(toks) if ch in "0123456789ABCDEF")
        if len(hexstr) % 2:
            hexstr = hexstr[:-1]
        data = bytes.fromhex(hexstr)
        if not data:
            return {}

        pos = 1 if data[0] == 0x41 else 0  # skip optional mode byte
        out: dict[str, str] = {}
        for pid in pids:
            pid_num = int(pid[2:], 16)
            nbytes = PID_DATA_LEN.get(pid.upper(), 1)
            if pos >= len(data) or data[pos] != pid_num:
                break  # device stopped here — caller falls back to serial
            out[pid.upper()] = data[pos + 1 : pos + 1 + nbytes].hex()
            pos += 1 + nbytes
        return out


# Scanner


async def scan() -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def callback(device, adv):
        name = device.name or ""
        if any(name.startswith(p) for p in SCAN_NAME_PREFIXES):
            if device.address not in seen:
                seen.add(device.address)
                found.append((device.address, name))
                print(f"  Found: {name:<20}  {device.address}  RSSI {adv.rssi} dBm")

    print("Scanning for BlueDriver (10 s)...")
    async with BleakScanner(detection_callback=callback):
        await asyncio.sleep(10.0)
    return found


# Helpers for the CLI

LIVE_PIDS = [
    ("010C", "RPM    "),
    ("010D", "Speed  "),
    ("0105", "Coolant"),
    ("0104", "Load   "),
    ("0111", "Throt  "),
    ("010B", "MAP    "),
]

HELP = """
Commands:
  <PID>     OBD command, e.g.  010C  0105
  live      Poll RPM/speed/coolant/load/throttle/MAP (Ctrl-C to stop)
  livefast  Same, but one combined multi-PID request
  info      Battery (PID 0142) + protocol (LMDP)
  debug     Toggle verbose fragment logging
  help      This message
  quit      Disconnect and exit

Common PIDs:
  010C RPM         010D speed       0105 coolant
  010F intake      0104 load        0111 throttle
  012F fuel level  0142 ECU volts   010B MAP
  0100 supported   0101 monitor
"""


async def cmd_live(bd: BlueDriverClient, multi: bool = False):
    """
    The live telemetry data logging loop (RPMs, Coolant temp, etc.)
    """
    import time

    mode = "combined single-request" if multi else "tight serial"
    print(f"\nLive data ({mode}) — Ctrl-C to stop\n")
    pid_list = [pid for pid, _ in LIVE_PIDS]
    last_print = time.monotonic()
    cycles = 0
    fps = 0.0
    try:
        while True:
            t0 = time.monotonic()
            if multi:
                data_map = await bd.send_pids_multi(pid_list)
                if len(data_map) < len(pid_list):
                    print(
                        f"  Combined request returned only {len(data_map)}/"
                        f"{len(pid_list)} PIDs — using serial.\n"
                    )
                    multi = False
                    continue
            else:
                # Strict serial: each send_pid waits for '>' before the next
                # command goes out. Pipelining is deliberately NOT used — a new
                # serial byte aborts the ELM327's in-flight query.
                data_map = {}
                for pid in pid_list:
                    data_map[pid] = await bd.send_pid(pid, timeout=1.0)
            cycle_ms = (time.monotonic() - t0) * 1000

            parts = []
            for pid, label in LIVE_PIDS:
                data = data_map.get(pid, "")
                val = decode_pid_value(pid, data) if data else "—"
                parts.append(f"{label}: {val:>10}")
            cycles += 1
            now = time.monotonic()
            if now - last_print >= 1.0:
                fps = cycles / (now - last_print)
                cycles = 0
                last_print = now
            line = (
                "  "
                + " | ".join(parts)
                + f"    [{fps:.1f} Hz | {cycle_ms:.0f} ms/cycle]"
            )
            print(line.ljust(140), end="\r", flush=True)
    except KeyboardInterrupt:
        print()


PROTOCOL_NAMES = {
    "0": "Auto",
    "1": "SAE J1850 PWM",
    "2": "SAE J1850 VPW",
    "3": "ISO 9141-2",
    "4": "ISO 14230-4 / KWP (5 baud)",
    "5": "ISO 14230-4 / KWP (fast)",
    "6": "ISO 15765-4 / CAN 11-bit / 500kbps",
    "7": "ISO 15765-4 / CAN 29-bit / 500kbps",
    "8": "ISO 15765-4 / CAN 11-bit / 250kbps",
    "9": "ISO 15765-4 / CAN 29-bit / 250kbps",
    "A": "SAE J1939 CAN",
}


async def cmd_info(bd: BlueDriverClient):
    # The BGX13P firmware intercepts ATRV/ATDP and returns NO DATA.
    # Use PID 0142 (ECU module voltage) and LMDP (proprietary) instead.
    volts_hex = await bd.send_pid("0142", timeout=2.0)
    volts = decode_pid_value("0142", volts_hex) if volts_hex else "—"
    print(f"  Battery : {volts} (via PID 0142)")

    raw = await bd._send_recv("LMDP", timeout=2.0)
    proto_raw = bd._clean(raw)
    # LMDP response format: "<number>\rOK" → after _clean → "<number> OK"
    proto_num = proto_raw.split()[0] if proto_raw else ""
    proto_name = PROTOCOL_NAMES.get(proto_num.upper(), f"unknown ({proto_raw})")
    print(f"  Protocol: {proto_num} => {proto_name}  (via LMDP)")


# Main func


async def main():
    global DEBUG
    args = sys.argv[1:]
    if "--debug" in args:
        DEBUG = True
        args.remove("--debug")
    address = args[0] if args else None

    if not address:
        devices = await scan()
        if not devices:
            print("\nNo BlueDriver found. Make sure it's plugged into a car")
            print("with ignition/ACC on, and no other device is connected to it.")
            return
        if len(devices) == 1:
            address, name = devices[0]
            print(f"\nUsing: {name}  [{address}]")
            print(f"Next time:  python3 {sys.argv[0]} {address}\n")
        else:
            print()
            for i, (a, n) in enumerate(devices):
                print(f"  [{i}] {n}  {a}")
            address, _ = devices[int(input("Select: "))]

    print(f"\nConnecting to {address} ...")
    bd = BlueDriverClient(address)
    try:
        await bd.connect()
        print("  Connected ✓")
        await bd.setup()
        print("\nRunning LM init dance...")
        await bd.lm_init()
        print(HELP)
        print("Ready.\n")

        loop = asyncio.get_event_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, lambda: input("obd> ").strip())
            except EOFError, KeyboardInterrupt:
                print()
                break
            if not line:
                continue
            cmd = line.lower()
            if cmd in ("quit", "exit", "q"):
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "live":
                await cmd_live(bd)
            elif cmd == "livefast":
                await cmd_live(bd, multi=True)
            elif cmd == "info":
                await cmd_info(bd)
            elif cmd == "debug":
                DEBUG = not DEBUG
                print(f"  Debug logging: {'ON' if DEBUG else 'OFF'}")
            else:
                resp = await bd.send(line.upper())
                cleaned = bd._clean(resp)
                print(f"  {cleaned if cleaned else '(no response)'}")
    finally:
        await bd.disconnect()
        print("Disconnected.")


if __name__ == "__main__":
    asyncio.run(main())
