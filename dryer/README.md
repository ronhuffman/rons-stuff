# Dryer Pico — MicroPython 5.0.0

Monitors dryer vibration using an MPU6050 and room illumination using a BH1750. Local sensors use I2C0, SDA GP0, SCL GP1, addresses `0x68` and `0x23`. The inspected installation uses Raspberry Pi Pico 2 W / RP2350 with MicroPython 1.28.0. Check the actual sensor breakout, voltage, pinout and wiring before copying this setup; the source is not a complete electrical wiring guide.

The Pico controls a shared Kauf bulb for dryer-complete and extended-room-light alerts. Civil twilight calculations use the installation's location and an NTP-set clock.

## Public example versus installed application

This source comes from the configured 5.0.0 application that passed a real Wi-Fi update. Its build ends in `-public-example`; the bulb address/entity and geographic coordinates are sanitized. It has not been installed in this form. The original detection thresholds and retained decision functions are unchanged, but zero coordinates would give the wrong local darkness gate.

Cooperative networking keeps local sampling separate from connection retries and bounded bulb requests. It adds saved calibration, sample-validity checks, recovery state, diagnostics, a watchdog and A/B application updating. These changes do not prove which fault caused any earlier outage.

## Configure a private deployment copy

1. Make a separate private deployment folder. Copy `pico_config.example.json` to `pico_config.json` and fill in Wi-Fi credentials plus an independent random token of at least 32 characters. See [security](../SECURITY.md).
2. Set `BULB_IP`, `BULB_LIGHT_ENTITY`, `LOCATION_LATITUDE` and `LOCATION_LONGITUDE` in `dryer_a.py` for the installation. The entity is the bulb's actual URL-encoded light name. `192.0.2.*`, `Laundry%20Indicator` and zero coordinates are placeholders. Configure a reachable numeric IPv4 NTP server if the example provider is unsuitable.
3. Copy that application to `dryer_b.py`; keep the two initial slots identical. Configured source contains installation details, so keep it outside the public repository.

## Initial USB installation — once

Back up the actual Pico files. Keep both washer and dryer stopped and the Pico still in its normal installed orientation for calibration. Inspect any existing `boot.py` before changing startup behavior.

Copy exactly `pico_config.json`, `dryer_a.py`, `dryer_b.py`, then the small **`main.py` launcher last** to the Pico filesystem root. Do not copy tests, docs or the Windows script. Hardware-reset and leave Thonny disconnected while verifying independent startup on normal power.

The first calibration collects 100 samples and saves a baseline; later boots reuse it. Check `/status` for version, increasing uptime, `accel_ok`, `lux_ok`, `baseline_ready`, valid time and plausible fresh measurements. Confirm HA and any existing laptop monitor still read correctly. The optional TCP port 5000 CSV interface is retained; it is not an update port.

## Later application updates over Wi-Fi

Use the private deployment folder on Windows, its matching private configuration and compatible configured dryer application. Keep both appliances still, with no alert work pending, and wait for `update_allowed`.

```powershell
$dryerAddress = Read-Host 'Actual dryer Pico LAN IPv4 address'
.\Update-Dryer.ps1 -PicoAddress $dryerAddress -StatusOnly
.\Update-Dryer.ps1 -PicoAddress $dryerAddress -Firmware .\dryer_a.py
```

The helper transfers the file to the inactive slot, verifies its hash, observes the reboot and confirms after healthy startup checks. Leave it open until success. The source filename does not select the destination slot. **Do not upload the launcher `main.py`.**

An unconfirmed trial attempts fallback after about three minutes. If an update is interrupted, inspect status and let fallback finish before retrying. Do not blindly use `-ConfirmOnly`: dryer 5.0.0 lacks the washer updater's individual-device checks and hash-bound confirmation. See [security](../SECURITY.md).

Only application code is Wi-Fi-upgradable; launcher, private settings, runtime and hardware repairs can still need USB. See [shared recovery notes](../shared-and-home-assistant/README.md).

## Tests and acceptance

From this folder on a Windows computer with Python:

```powershell
python -B .\test_firmware.py -v
python -B .\test_windows_updater.py
```

The tests use simulated hardware; the Windows helper test uses local loopback TCP only. Read [TESTING.md](../TESTING.md) for the distinction between desktop fault tests, previously observed hardware startup/update and the full physical-cycle/endurance checks still pending.
