# Validation and current status

Snapshot date: September 13, 2026. Separate three kinds of evidence: desktop tests on this public copy, earlier observations of the configured physical devices, and acceptance checks still pending.

## Public snapshot desktop tests

The public washer and dryer source copies passed their existing suites after sanitization:

| Check | Result |
| --- | --- |
| Washer regression/fault-injection suite | 84 passed |
| Dryer regression/fault-injection suite | 48 passed |
| Washer Windows PowerShell + real loopback TCP updater cases | 8 passed |
| Dryer Windows PowerShell + real loopback TCP updater scenario | 1 passed |
| Public snapshot/YAML/document-link checks | 5 passed |

Both launchers and both distinct applications compiled with MicroPython `mpy-cross` 1.29.0 (Python package `mpy-cross==1.29.0.post2`), emitting format 6.3. A/B applications were byte-identical within each device folder, so the B copies were not compiled separately. No `.mpy` artifacts are distributed. Compilation checks syntax, not runtime/hardware behavior. Both Windows helpers also passed PowerShell syntax parsing.

An AST comparison against the configured upgrade packages verified that all application nodes outside the explicitly sanitized settings/build label were unchanged and that both launchers were byte-identical. A local privacy check found none of the known real Wi-Fi credentials, update tokens, device identity, installation addresses, coordinates or hardware identifiers in this public tree. This is a targeted review, not a guarantee that arbitrary future edits are safe to publish.

Firmware tests cover network retry/listener recovery, bounded HTTP handling, stale/missing observations, alert retry/acknowledgment, watchdog progress, authenticated inactive-slot uploads, interrupted or invalid uploads, trial confirmation/fallback and tick wrap. Washer tests additionally cover device identity, post-upload fresh idle readings, hash-bound confirmation and comparison against the original valid-input decision fixture.

The loopback tests invoke the actual Windows helper and firmware HTTP parser, but simulate hardware and reboots and accelerate trial timing. They do not contact the installed devices. The dryer test path was made portable for its new folder; both Windows helpers now require an explicit target address.

Additional snapshot checks parse the three YAML examples with duplicate-key rejection, check secret references and dashboard dependencies, verify identical A/B files and unusable placeholder credentials, and resolve relative documentation links. This is not Home Assistant's runtime configuration validator.

To repeat on Windows with Python, from the repository root:

```powershell
python -B .\washer\test_firmware.py -v
python -B .\dryer\test_firmware.py -v
python -B .\washer\test_windows_updater.py
python -B .\dryer\test_windows_updater.py
python -m pip install -r .\requirements-test.txt
python -B .\test_public_snapshot.py -v
```

The firmware suites use the Python standard library; only the snapshot/YAML checks need PyYAML. Tests intentionally include fixed fake SSIDs, passwords and update tokens. Those fixtures are not deployment credentials.

## Previously observed on configured hardware

The following records concern the private configured builds, before public addresses/location were replaced and the public build suffix was added. Their file hashes therefore **must not match** the public applications.

| Item | Washer | Dryer |
| --- | --- | --- |
| Application version | 6.0.0 | 5.0.0 |
| Hardware/runtime | Pico 2 W / RP2350, MicroPython 1.28.0 | Pico 2 W / RP2350, MicroPython 1.28.0 |
| Real same-version Wi-Fi update | A to B; hash checked and trial confirmed | A to B; hash checked and trial confirmed |
| Normal-power startup | User confirmed separate power supply; increasing post-restart uptime and healthy status observed | Startup with Thonny disconnected on normal power observed |
| Physical completion cycle | Not yet verified | Not yet verified |

Configured washer application SHA-256:
`59236b8b8d8fd55957dd5b5f60430ce9166efcfdc511d2406f6b465bf1505ee1`

Configured dryer application SHA-256:
`cf6cba07649dbe56c4f4e6c1b61cb7ce982e48d8013fc1dcb8be3d21023f718c`

Healthy status snapshots and initial HA readings are point-in-time observations, not an endurance test. Per-boot reconnect/listener counters include initial setup. A numeric reset-cause code alone does not establish a power-fault diagnosis.

Before public sanitization, comparison with the supplied originals verified six retained washer functions and 17 retained dryer functions plus their original non-secret constants. Public redaction intentionally changes network targets, bulb entity, dryer coordinates and build label, not detection functions or thresholds. The historical outage cause remains unproven.

## Not established

- A full physical wash/dry cycle with the upgraded code, normal Kauf power-cycle acknowledgment, or overlapping alerts from both monitors.
- End-to-end HA/Echo acknowledgment. The existing HA REST command was inspected but not invoked during repository preparation.
- Long-duration RF/memory reliability, deliberate physical power-cut during flash writes, or bad-firmware rollback on the actual boards. Desktop fault tests are not substitutes.
- Runtime validation of the sanitized HA package/dashboard on a separate HA instance or execution of public-example source on hardware.
- A guarantee that future hardware, filesystem, power or launcher/runtime problems can be repaired without USB.

No Pico, appliance relay, bulb or live HA configuration was changed while preparing this public snapshot.
