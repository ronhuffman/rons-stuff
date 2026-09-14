# Ron's Stuff

Personal laundry-monitor projects: MicroPython on Raspberry Pi Pico 2 W, Wi-Fi application updates, a shared Kauf indicator bulb, and Home Assistant integration.

This is a **sanitized public-source snapshot**, prepared September 13, 2026. It is separate from any private work repository. It contains no working Wi-Fi credentials, update tokens or installation addresses. The example settings must be customized before installation; do not upload these public files over an already working installation unchanged.

## Contents

| Folder | Contents |
| --- | --- |
| [washer](washer/README.md) | Washer 6.0.0 application, A/B launcher, Windows Wi-Fi updater, configuration example and tests |
| [dryer](dryer/README.md) | Dryer 5.0.0 application, A/B launcher, Windows Wi-Fi updater, configuration example and tests |
| [shared-and-home-assistant](shared-and-home-assistant/README.md) | How the Picos, Shelly, shared Kauf bulb and HA relate; selected, sanitized HA configuration and dashboard |

## Current project status

Both configured devices previously completed initial installation and a real same-version Wi-Fi application update from slot A to slot B, including hash verification and healthy confirmation. Those observations concern the private, configured builds, **not this public-example build**. See [validation and remaining checks](TESTING.md) for the evidence boundary.

The networking changes add bounded network operations, Wi-Fi recovery, diagnostics, an eight-second watchdog and authenticated A/B application updates. The appliance-detection thresholds and retained decision functions were preserved. This does not establish the cause of the historical dryer outages or guarantee that hardware/power faults have been eliminated.

Public applications keep versions 6.0.0/5.0.0 but use a `-public-example` build suffix. Addresses, the bulb entity and dryer location are placeholders. The Windows helpers require an explicit `-PicoAddress`. Publication preparation did not modify either installed Pico or live HA configuration.

## Read before using

- Start with the relevant device README and [security notes](SECURITY.md). Each Pico needs its own private configuration and independent random update token.
- Wireless updating replaces an application slot, not MicroPython, the launcher or private configuration. Some repairs still require USB access.
- Updates use unencrypted HTTP on a trusted LAN. Do not expose these endpoints to the internet.
- Both Picos control the same bulb directly. Simultaneous alerts can compete; no central shared-bulb arbitration has been implemented.
- Full physical appliance cycles, combined bulb acknowledgment and long-term reliability still need acceptance testing. Desktop simulations are not those tests.

## License

No license has been selected for this snapshot. No third-party licensing choice has been made on the owner's behalf.
