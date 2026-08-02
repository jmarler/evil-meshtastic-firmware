# evil-meshtastic-firmware

Modified [Meshtastic](https://meshtastic.org) firmware with offensive
security-research features (an "evil node"), built for a DEF CON Ham Radio
Village talk demonstrating attack surface in the Meshtastic mesh protocol.

Based on Meshtastic firmware **v2.7.15**. Licensed under **GPL-3.0** (see
[`LICENSE`](LICENSE) and [`NOTICE`](NOTICE)).

> ⚠️ **Read this first.** This firmware deliberately misbehaves on a mesh:
> it can drop, modify, amplify, and forge traffic. It is published for
> **education and authorized security research only**. Run it only on radios
> and a mesh you own or have explicit permission to test. Do **not** run it on
> shared or public Meshtastic networks. Interfering with radio communications
> you are not authorized to touch is illegal in most jurisdictions. Be
> responsible, and don't be a jerk on the real mesh.

## What it does

The evil features are implemented in a small, self-contained set of modules
(`src/mesh/EvilNode.*`, `src/mesh/EvilCtrlModule.*`,
`src/graphics/draw/EvilStatusRenderer.*`) plus a handful of hooks into the
stock router. Each capability is gated behind a build flag:

| Capability | Build flag | Effect |
|---|---|---|
| Source-ID override | `EVIL_ALLOW_FROM_OVERRIDE` | Lets the host API set an arbitrary source node ID (spoofing) |
| MitM transform | `EVIL_TRANSFORM_ROT13` | Rewrites text payloads in transit (ROT13 demo) |
| Selective drop | `EVIL_DROP_RATE=<n>` | Silently drops n% of relayed packets (black hole) |
| Hop amplification | `EVIL_HOP_MAX` | Forces hop_limit to max before rebroadcast |
| NodeDB flood | `EVIL_NODEINFO_FLOOD` / `EVIL_FLOOD_WITH_KEY` | Injects ghost nodes to exhaust the NodeDB |

None of these are novel zero-days. They exploit **already-documented**
limitations of Meshtastic's PSK/AES-CTR channel model. The point of the project
is how quickly a working attack toolkit came together — most of this firmware
was written by two people who had never touched firmware before, working with a
coding agent.

## Build

Requires [PlatformIO](https://platformio.org).

```bash
# Clone the firmware repo. The two TFT builds also need the device-ui fork
# checked out as a sibling directory, so clone both side by side:
git clone --recursive https://github.com/jmarler/evil-meshtastic-firmware
git clone https://github.com/jmarler/evil-meshtastic-device-ui
cd evil-meshtastic-firmware
# pick the environment for your board:
pio run -e heltec-v3-evil-full        # Heltec WiFi LoRa 32 V3 (OLED) — no device-ui needed
pio run -e heltec-v4-tft-evil-full    # Heltec V4 TFT        (needs ../evil-meshtastic-device-ui)
pio run -e t-deck-tft-evil            # LilyGo T-Deck console (needs ../evil-meshtastic-device-ui)
# flash:
pio run -e heltec-v3-evil-full -t upload
```

The generated protobuf sources are committed in-tree, so a normal build does
not require regenerating from the `protobufs` submodule. The TFT environments
pull the on-device UI from the sibling `evil-meshtastic-device-ui` checkout via
a local `symlink://` lib dependency.

## Related repos

- [evil-meshtastic](https://github.com/jmarler/evil-meshtastic) — project overview
- [evil-meshtastic-tools](https://github.com/jmarler/evil-meshtastic-tools) — Python attack toolkit
- [evil-meshtastic-device-ui](https://github.com/jmarler/evil-meshtastic-device-ui) — evil "Dangerous Features" panel for the T-Deck

## Attribution

This is a modified version of Meshtastic firmware. Meshtastic is a registered
trademark of Meshtastic LLC. This project is **not affiliated with or endorsed
by** the Meshtastic project. See [`NOTICE`](NOTICE).
