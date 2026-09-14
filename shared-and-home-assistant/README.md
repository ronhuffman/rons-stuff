# Shared equipment and Home Assistant

This folder documents the relationships actually found in the inspected setup on September 13, 2026. It is a selected, sanitized export, **not a complete Home Assistant backup** and not a configuration installed by this publication task.

## Relationships

```text
Shelly plug -- watts over LAN --> Washer Pico -- completion colors --+
                                                                   |
MPU6050 + BH1750 -- local I2C --> Dryer Pico -- completion/light ----+--> Shared Kauf bulb

Home Assistant -- GET /status --> Washer Pico and Dryer Pico
Home Assistant -- POST /ack ----> Washer Pico only
Windows updater -- authenticated application upload --> matching Pico
```

Each Pico also reads the bulb's uptime. A confirmed uptime decrease after power cycling is used as acknowledgment; a temporary inability to reach the bulb is not enough by itself. Pending OFF work is retried. Both controllers can issue commands independently, so one appliance's alert or delayed OFF can interfere with the other. A coordinated owner for the shared lamp is a possible future improvement, not a feature in this snapshot.

The Shelly integration separately provides HA's washer-plug electrical measurements. The Pico itself reads Shelly power directly. HA displays monitor status; it is not required to execute the Picos' detection or bulb-color decisions.

## Included HA files

- `home-assistant/laundry-package.example.yaml`: the inspected REST sensors, washer acknowledgment REST command, and dryer sensor/binary-sensor templates, regrouped into one example package. Device URLs use `!secret` references instead of installation addresses.
- `home-assistant/secrets.example.yaml`: URL placeholders for that package. These are not working credentials or addresses.
- `home-assistant/dashboard.example.yaml`: the inspected washer, dryer and lighting sections, with identifying Shelly entity IDs replaced by generic placeholders. Unrelated room-weather cards and the external sun-elevation card are omitted. The washer temperature label spelling is corrected.

No washer/dryer-specific entries were found in the inspected `automations.yaml` or `scripts.yaml`; their unrelated contents are not included. This does not assert that every UI integration or automation elsewhere in HA was exhaustively exported. No private `secrets.yaml`, `.storage`, database, backup, unrelated service URLs or ingress links are included.

## Adapting the HA examples

Do not paste this over the existing working configuration. Back up your HA setup and resolve duplicate names/unique IDs first. In the inspected system these definitions already exist in the main configuration; adding the package alongside them would duplicate definitions.

For a new installation, one explicit package include can be merged under the existing `homeassistant:` key in `configuration.yaml`:

```yaml
homeassistant:
  packages:
    laundry: !include packages/laundry.yaml
```

Place the customized package at `packages/laundry.yaml`. Do not create a second `homeassistant:` key or duplicate an existing `packages:` mapping. See HA's [package configuration documentation](https://www.home-assistant.io/docs/configuration/packages/).

Add the three keys from `secrets.example.yaml` to your private HA `secrets.yaml`, replacing each URL with the actual endpoint. Keep an existing secrets file and its other entries intact. `!secret` separates settings; it does not encrypt them. See [HA secrets documentation](https://www.home-assistant.io/docs/configuration/secrets/).

The REST sensors poll every 15 seconds. The washer uses a 5-second request timeout; the dryer uses 10 seconds. The package preserves the selected fields and template behavior of the inspected configuration. See the [REST sensor documentation](https://www.home-assistant.io/integrations/sensor.rest/) for integration options.

Check the resulting entity IDs locally: an existing entity registry can assign different names. Map these dashboard placeholders to entities supplied by your Shelly integration:

| Dashboard placeholder | Required measurement |
| --- | --- |
| `sensor.washer_plug_current` | Plug current |
| `sensor.washer_plug_power` | Plug power |
| `sensor.washer_plug_voltage` | Plug voltage |
| `sensor.washer_plug_temperature` | Plug internal temperature |

The package does not create those four entities. Dashboard YAML is a separate dashboard definition, not another package to load. Review it in a new/test dashboard instead of overwriting the current dashboard. The washer acknowledgment action is `rest_command.washer_acknowledge`; an Echo/voice integration is **not** included or verified here.

Run HA's own configuration check before applying changes. The snapshot's offline YAML checks do not replace validation by the installed HA version or a live entity/acknowledgment test.

## Existing HA diagnostic limitations

The selected templates check whether the base REST sensor is unknown/unavailable and use numeric defaults such as `float(0)`. They do not explicitly use every new Pico validity/error field. In particular, a reachable dryer with an invalid individual sensor can still produce a numeric zero in one of these templates. That is existing behavior preserved for this export, not a claim that zero proves a valid measurement.

New health entities for Wi-Fi, data age/validity, sensor errors, trial/slot and last fault would be a useful separate change. They are not silently added to the live setup or represented as existing exports here.

## Shared USB recovery notes

The launcher starts an approximately eight-second watchdog. Stopping the program in Thonny does not disable an already running watchdog. For extended USB maintenance, stop the program and promptly create `maintenance.flag` through the Pico REPL before the next reset:

```python
open("maintenance.flag", "w").close()
```

On the next hardware/watchdog reset, the launcher leaves the application and watchdog off. Monitoring and Wi-Fi updating are disabled. After completing repair, resume with:

```python
import os, machine
os.remove("maintenance.flag")
machine.reset()
```

This is a deliberate local USB operation, not a remote endpoint. If the REPL or filesystem is unavailable, physical BOOTSEL recovery may still be required. Preserve private configuration/backups and do not return a partial installation or a board with the maintenance flag to service.

## Remaining integration acceptance

At a convenient time, verify full washer and dryer cycles, real bulb power-cycle acknowledgment, simultaneous/overlapping alerts, and the HA acknowledgment action. Any controlled network-loss or power-interruption test needs separate approval and should not disrupt household networking. No such destructive or appliance-control test was performed for this repository preparation.
