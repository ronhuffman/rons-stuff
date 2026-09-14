# Washer Pico — MicroPython 6.0.0

Reads a Shelly plug's power measurements to track washer activity and drives a Kauf bulb for completion alerts. The monitored installation uses Raspberry Pi Pico 2 W / RP2350 with MicroPython 1.28.0. The application reads the Shelly; it does not command its appliance-power relay.

## Public example versus installed application

This source is derived from the configured 6.0.0 build that passed a real Wi-Fi update. Its build identifier ends in `-public-example`; the network addresses and bulb entity are sanitized. It has not been installed on an appliance in this form. Thresholds are specific to the original washer, not universal settings for every model.

The six retained detection functions have an independent fixture in `original_logic.py`; it is a desktop test reference, not a Pico startup file. Networking changes invalidate stale readings, preserve known progress and defer decisions when observations are missing. The washer cannot measure activity during Wi-Fi/Shelly outages; it cannot reconstruct a cycle it did not observe.

## Configure a private deployment copy

1. Keep the public repository unchanged and make a separate private deployment folder.
2. Copy `pico_config.example.json` to `pico_config.json` there. Enter the actual Wi-Fi credentials, a new random token of at least 32 characters and an individual `DEVICE_ID` beginning with `washer-`. Keep `DEVICE_TYPE` as `washer`. See [security](../SECURITY.md) for token generation.
3. In `washer_a.py`, set `SHELLY_IP`, `SWITCH_ID`, `BULB_IP` and `BULB_LIGHT_ENTITY` to match the installation. The entity must be the bulb's actual URL-encoded light name. `192.0.2.*` addresses and `Laundry%20Indicator` are documentation placeholders, not discovery results.
4. Copy the configured application to `washer_b.py` so both initial slots match. Keep configuration and both slots private once customized. Check hardware/API compatibility before using another Shelly or bulb.

## Initial USB installation — once

Back up the actual Pico files first. Keep the washer idle and the Pico accessible. Inspect any existing `boot.py` before changing startup behavior.

Copy these four files to the Pico filesystem root using Thonny: `pico_config.json`, `washer_a.py`, `washer_b.py`, then the small **`main.py` launcher last**. Do not copy tests, the fixture, Windows helper or docs. Both initial slots are the new application, not the old program.

Hardware-reset and verify independent startup on normal power with Thonny disconnected. Open the Pico's `/status`: confirm version, `device_type`, individual ID, increasing uptime, connected Wi-Fi/Shelly and fresh plausible watts. A sleeping washer normally reports `internal_state: READY`.

Initial healthy startup requires at least 60 continuously healthy seconds. Updating also requires observed READY/standby power for at least 30 seconds and no pending bulb work. Use `update_allowed`; do not infer eligibility only from elapsed time.

## Later application updates over Wi-Fi

Use the private deployment folder on Windows and its matching private configuration. Keep the washer idle and Thonny disconnected until success. In PowerShell, enter the actual numeric private address at the prompt:

```powershell
$washerAddress = Read-Host 'Actual washer Pico LAN IPv4 address'
.\Update-Washer.ps1 -PicoAddress $washerAddress -StatusOnly
.\Update-Washer.ps1 -PicoAddress $washerAddress -Firmware .\washer_a.py
```

The helper checks device identity, application type, size and hash; writes the inactive slot; requires a new post-upload idle Shelly reading; observes the trial reboot and confirms after the real healthy interval. It chooses the destination slot regardless of the input filename. **Never send the launcher `main.py` as an application.**

Leave the window open until success. An unconfirmed trial attempts fallback after about three minutes. If interrupted, inspect status and let fallback finish before retrying. `-ConfirmOnly` is for deliberately accepting a trial matching the selected application file, not bypassing a failed validation. Updates reboot the monitor and are not uninterrupted monitoring.

Wi-Fi updates do not replace the launcher, configuration, MicroPython runtime or bootloader. Read [shared installation/recovery notes](../shared-and-home-assistant/README.md) before returning hardware to an inaccessible location.

## Tests and integration

On Windows with Python, from this folder:

```powershell
python -B .\test_firmware.py -v
python -B .\test_windows_updater.py
```

The second script uses real Windows PowerShell and loopback TCP with simulated hardware and accelerated trial time; it never contacts a Pico. See [TESTING.md](../TESTING.md) for coverage and unverified physical tests, and [HA integration](../shared-and-home-assistant/README.md) for the status sensor and existing acknowledgment route.
