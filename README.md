# Reverse Engineering the BlueDriver OBD-II Scanner

This is a summary of my findings from reverse-engineering the BLE communication between the BlueDriver OBDII port scanner and the iOS app, using HCI capture of the Bluetooth pairing process and live data transmitting. This was then replicated as a Python CLI application using the [`bleak` library](https://github.com/hbldh/bleak) for BLE communication.

Hopefully this helps with creating more open source tools, freeing the hardware to be used with more than a single proprietary app.


> Reverse engineering was performed solely for interoperability purposes. No proprietary code or binaries were copied or distributed.
> This isn't affiliated with or endorsed by BlueDriver, it's just a protocol analysis tool for educational use only.


## Usage

You can use `pip` or `uv sync` for installing dependencies (see [`pyproject.toml`](./pyproject.toml)).

Then use `python` or `uv run` to run the tool script.

> [!IMPORTANT] 
> To connect, have the car with ignition/ACC on, then plug the BlueDriver in and run the script in succession.
>
> If you're having issues, make sure no other device is connecting to the scanner.

```
python main.py           # BLE scan to find the device for initial pairing
python main.py <UUID>    # directly connects to the Bluetooth UUID address
python main.py --debug   # verbose fragment logging
```

## Reverse Engineering Process

Because the app utilizes BLE communication to read vehicle data from the OBD-II port scanner, I was able to utilize Apple developer tools to sniff BLE packets between the app and device. [This guide from Apple](https://download.developer.apple.com/iOS/iOS_Logs/Bluetooth_Logging_Instructions.pdf) was especially helpful with learning how to log BLE communication from my phone.

1. Download the Bluetooth (for iOS) [logging profile](https://developer.apple.com/feedback-assistant/profiles-and-logs/) from Apple Developer and install it.
2. Unpair the scanner from my phone and unplug it so that you can repeat the pairing process in order to figure out how to replicate it.
3. **Note the current time** so that you know which logs to read later (because there will be a LOT).
4. Trigger a sysdiagnose by firmly pressing (and shortly holding) both volume buttons + Side (or Top) button. You'll feel the phone vibrate indicating the sysdiagnose was triggered correctly.
5. Wait a couple of minutes for the diagnostic gathering to complete.
6. Go to Settings > Privacy > Analytics & Improvements > Analytics Data and search for `sysdiagnose`. You should see a `.tar.gz` archive timestamped with the date and time you triggered it.
7. Press share to send the file to your computer (you can AirDrop to your Mac).
8. On Mac, download the Additional Tools for Xcode, then copy the `Additional Tools.dmg/Hardware/PacketLogger.app` to your Downloads. You'll need this to analyze the packet logs.
9. Unarchive the `sysdiagnose` and open the `sysdiagnose/logs/Bluetooth/bluetoothd-hci-latest.pklg` packet logs file with the `PacketLogger.app` app.
10. You can then analyze the pairing and live car telemetry Bluetooth packets starting from the timestamp that you noted down.

---

## Findings

### Device Identification

- **BLE name prefixes:** Appears as either `BlueDriv` or `LSB2-`
- **Underlying chipset:**
  - Silicon Labs `BGX13P` acts as the higher level firmware overlay managing BLE and device state.
  - `ELM327` lower layer that bridges the OBD-II communication.
- **Firmware/model strings:** Can be found in the standard Device Information GATT service as `0x2A26` and `0x2A24`.

### GATT Service Map

| Characteristic | UUID | Properties | Purpose |
|---|---|---|---|
| CMD | `a9da6040-0823-4995-94ec-9ce41ca28833` | write-without-response, write, notify | Send commands; receive ACKs |
| DATA | `a73e9a10-628f-4494-a099-12efaf72258f` | write-without-response, notify, indicate | Flow-control writes; receive ELM327 response fragments |
| STATUS | `75a9f022-af03-4e41-b4bc-9de90a47d50b` | read, write, notify, indicate | Device status bursts |
| ENCRYPTED | `12e868e7-c926-4906-96c8-a7ee81d4b1b3` | read (encryption required) | Pairing trigger — reading this initiates SMP bonding |

### Pairing / Security

- CoreBluetooth has no explicit pairing API, it's triggered by reading the encrypted characteristic.
- The device's SMP Pairing Response is a `IO = NoInputNoOutput`, forcing `Secure Connections Just Works` regardless of what the host requests.
  - This means the pairing is actually pretty simple with no PIN or dialog, and macOS / iOS will keep the pairing future connections.
  - After you run the script on macOS, you'll see the scanner is saved in your Bluetooth device list.

### Wire Encoding

The device uses a **XOR cipher**, with the key being `0x26`, so every payload byte is XORed with `0x26`. However there are **two exceptions** that pass through unchanged:
- `0x0D` (`\r`)
- `0x3E` (`>`)

Since XOR is symmetric, the same key will both encode and decode.

```python
encoded_byte = b ^ 0x26  # (unless b == 0x0D or b == 0x3E)
```

### Command / Response Protocol

#### CMD Characteristic (phone → device)
- The app sends XOR-encoded ASCII commands that are terminated with `\r`.
- The device then replies with `01 01 00` (**ACK**) per command.
- On the initial connection, the device sends a `00 FF 07` status message.

#### DATA Characteristic
- Before sending any commands, it opens a 255-byte receive credit window, by writing `00 FF 7F` to DATA.
- Every incoming notification fragment must be ACKed immediately with `01 <len> 00`, where `<len>` is the exact byte count for that fragment.
  - Without per-fragment ACKs, the scanner just stops sending after the first fragment.
- The responses are XOR-decoded and accumulate in a buffer; completion is signalled by`>` (the ELM327 prompt).

#### Response Format
- ELM327 is configured by the LM init as: **echo OFF, headers OFF, linefeeds OFF, spaces ON, auto-protocol**.
- Example response to `010C` would be `0F 80 \r>`
  - Data bytes, space-separated, no mode/PID echo, terminated by `\r>`.
- Responses commonly arrive **split across two BLE fragments**, so you always need to wait for the `>` terminator before parsing.

### Proprietary LM Init Sequence

These commands are processed by the BGX13P firmware overlay (not the ELM327 core). They **must** be sent in this exact order before any OBD-II PIDs will work. Sending standard AT commands (ATZ, ATE0, etc.) after this messes up the firmware's state and causes it to send `NO DATA` on all queries after that.

1. Write `00 FF 7F` to DATA  (this opens the receive credit window).
2. Send the following commands over CMD and wait for the `>` terminator after each:

| Command | Expected Response | Notes |
|---|---|---|
| `LMI` | `?\r>` or `OSAPI v2.60\rOK\r>` | Firmware identity probe |
| `LMD` | `OK\r>` | |
| `LML0` | `?\r>` | |
| `LMI` | `OSAPI v2.60\rOK\r>` | |
| `LMD` | `OK\r>` | |
| `LMDP` | `<protocol#>\rOK\r>` | Returns auto-detected OBD protocol number |
| `LMI` | `OSAPI v2.60\rOK\r>` | |
| `LMX1` | `OK\r>` | Switch to exhaustive timing (~200 ms/query) |
| `LMX0` | `OK\r>` | Switch to fast timing (~45 ms/query) |

### LMX1 / LMX0 — Response Timing Modes
I found this while trying to figure out why my telemetry like RPMs were coming with ~1s delay all the time even though the app was much faster. That's when I realized the firmware actually requires you to switch to a lower latency mode:
- **LMX1 (exhaustive):** The firmware waits the full ~200 ms timeout per query regardless of ECU response time, which is ~4× slower for getting live data than the app is.
- **LMX0 (fast):** The firmware returns as soon as the ECU answers, much faster with ~45 ms per query. *Use this for live telemetry*.
- The iOS app uses LMX1 only for its one-time monitor/freeze-frame scan features, and uses LMX0 for live polling.

### OBD-II PIDs

- After the LM init, raw mode-01 PIDs (e.g. `010C\r`) work directly with no further AT-command setup.
- ATRV and ATDP return `NO DATA`, so use PID `0142` for battery voltage and `LMDP` for protocol detection instead.

#### Tested Live PIDs

| PID | Parameter | Formula |
|---|---|---|
| `010C` | Engine RPM | `((A << 8) \| B) / 4` RPM |
| `010D` | Vehicle speed | `A` km/h |
| `0105` | Coolant temperature | `A − 40` °C |
| `010F` | Intake air temperature | `A − 40` °C |
| `0104` | Engine load | `A × 100 / 255` % |
| `0111` | Throttle position | `A × 100 / 255` % |
| `012F` | Fuel level | `A × 100 / 255` % |
| `010B` | Intake manifold pressure | `A` kPa |
| `0142` | ECU module voltage | `((A << 8) \| B) / 1000` V |

#### Multi-PID Combined Requests
- OBD-II mode 01 allows up to **6 PIDs in a single request** (e.g. `010C0D05…`), costing one BLE round-trip instead of N.
- CAN vehicles answer all PIDs in one multi-frame response; non-CAN protocols do not support this — fall back to serial polling if the response is incomplete.
- **Pipelining does not work**, I tried this but sending a new command while an existing query is going just causes the lower level `ELM327` to abort the current query, causing timeouts.
- Combined response format: each PID number is echoed before its data bytes (no leading `0x41` mode byte); single-PID replies return data bytes only.

#### Live Data Timings
- Serial polling was about ~40–50 ms per PID, so about ~0.25–0.3 s for a 6-PID refresh, and seems to match the speed of the iOS app.
- BLE connection interval seems to be ~15 ms.

### OBD Protocol Numbers (LMDP)

You can find this and other constants within the script as well.

| # | Protocol |
|---|---|
| 0 | Auto |
| 1 | SAE J1850 PWM |
| 2 | SAE J1850 VPW |
| 3 | ISO 9141-2 |
| 4 | ISO 14230-4 / KWP (5-baud init) |
| 5 | ISO 14230-4 / KWP (fast init) |
| 6 | ISO 15765-4 / CAN 11-bit / 500 kbps |
| 7 | ISO 15765-4 / CAN 29-bit / 500 kbps |
| 8 | ISO 15765-4 / CAN 11-bit / 250 kbps |
| 9 | ISO 15765-4 / CAN 29-bit / 250 kbps |
| A | SAE J1939 CAN |
