/**
 * EvilNode.h — Evil Node feature hooks for security research
 *
 * Enabled by build flags in the evil-node PlatformIO environment.
 * All evil behaviour is compiled out when EVIL_NODE is not defined.
 *
 * Build flags (set in platformio.ini [env:heltec-v4-evil]):
 *
 *  -D EVIL_NODE=1               Master enable — required for all evil features
 *
 *  Source spoofing:
 *  -D EVIL_ALLOW_FROM_OVERRIDE=1   Allow Python API to set arbitrary from node ID.
 *                                  Removes the p.from=0 guard in MeshService.
 *
 *  Packet dropping:
 *  -D EVIL_DROP_RATE=25         Drop ~25% of relay packets (1–100, 0=disabled)
 *  -D EVIL_DROP_NODE=0xDEADBEEF Drop packets from this node ID (0=disabled)
 *  -D EVIL_DROP_CHANNEL=255     Drop packets on this channel index (255=disabled)
 *
 *  Hop limit manipulation:
 *  -D EVIL_HOP_MAX=1            Force hop_limit=7 on every relayed packet
 *                               (maximize propagation, ignore original limit)
 *  -D EVIL_HOP_KILL=1           Force hop_limit=0 on every relayed packet
 *                               (black-hole: packet dies after one more hop)
 *
 *  Decrypt-modify-re-encrypt (MitM on PSK channels):
 *  -D EVIL_TRANSFORM=1          Enable transform pipeline
 *  -D EVIL_TRANSFORM_ROT13=1    ROT-13 all text messages in transit
 *  -D EVIL_TRANSFORM_REVERSE=1  Reverse all text messages in transit
 *  -D EVIL_TRANSFORM_SUFFIX=1   Append EVIL_SUFFIX to all text messages
 *  -D EVIL_SUFFIX=\"— evil\"     Suffix string (default: " — [evil node]")
 *
 *  NodeInfo flooding (requires EVIL_ALLOW_FROM_OVERRIDE):
 *  -D EVIL_NODEINFO_FLOOD=1     Enable NodeInfo flood mode
 *  -D EVIL_FLOOD_COUNT=200      Number of fake nodes to inject (default: 200)
 *  -D EVIL_FLOOD_WITH_KEY=1     Include fake 32-byte public keys (resists eviction)
 *
 * Phase 4.1 additions:
 *  Runtime control via EvilCtrlModule (MeshModule on PRIVATE_APP portnum 256).
 *  EvilNode::state holds the current runtime configuration; all attack functions
 *  check it instead of compile-time #defines.  Compile-time flags become initial
 *  values so existing build environments still work unchanged.
 *
 * Project: Evil Meshtastic — DefCon 2026 HRV security research
 * See: notes/phase0-codebase-tour.md, GitHub Issue #4030
 */

#pragma once

#ifdef EVIL_NODE

#include "configuration.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include <stdint.h>
#include <string.h>

// Default values for optional flags (used to initialise RuntimeState)
#ifndef EVIL_DROP_RATE
#define EVIL_DROP_RATE 0
#endif
#ifndef EVIL_DROP_NODE
#define EVIL_DROP_NODE 0
#endif
#ifndef EVIL_DROP_CHANNEL
#define EVIL_DROP_CHANNEL 255
#endif
#ifndef EVIL_SUFFIX
#define EVIL_SUFFIX " \xe2\x80\x94 [evil node]"
#endif
#ifndef EVIL_FLOOD_COUNT
#define EVIL_FLOOD_COUNT 200
#endif

namespace EvilNode {

/**
 * Runtime configuration for all evil features.
 *
 * Initialised from compile-time #defines so existing build envs behave as
 * before.  EvilCtrlModule updates this struct at runtime when it receives an
 * EvilCtrlMsg packet addressed to the local node.
 *
 * transform values:  0=none  1=rot13  2=reverse  3=suffix
 * hop_mode values:   0=normal  1=max(7)  2=kill(0)
 */
struct RuntimeState {
    // --- transform ----------------------------------------------------------
#if defined(EVIL_TRANSFORM_ROT13)
    uint8_t transform = 1;
#elif defined(EVIL_TRANSFORM_REVERSE)
    uint8_t transform = 2;
#elif defined(EVIL_TRANSFORM_SUFFIX)
    uint8_t transform = 3;
#else
    uint8_t transform = 0;
#endif
    char suffix[65] = EVIL_SUFFIX;

    // --- packet drop --------------------------------------------------------
    uint32_t drop_rate    = EVIL_DROP_RATE;
    uint32_t drop_node    = EVIL_DROP_NODE;
    uint8_t  drop_channel = EVIL_DROP_CHANNEL;

    // --- hop limit ----------------------------------------------------------
#if defined(EVIL_HOP_MAX)
    uint8_t hop_mode = 1;
#elif defined(EVIL_HOP_KILL)
    uint8_t hop_mode = 2;
#else
    uint8_t hop_mode = 0;
#endif

    // --- node flood ---------------------------------------------------------
    // flood starts false; EvilCtrlModule triggers it on demand
    uint32_t flood_count = EVIL_FLOOD_COUNT;
#if defined(EVIL_FLOOD_WITH_KEY)
    bool flood_keys = true;
#else
    bool flood_keys = false;
#endif
};

/** Live runtime state — read by shouldDrop / transformPacket / manipulateHopLimit. */
extern RuntimeState state;


/**
 * Called from Router::perhapsHandleReceived() — BEFORE handleReceived().
 *
 * Returns true if the packet should be SILENTLY DROPPED (not relayed, not
 * delivered to modules, not sent to phone).
 *
 * Implements: selective packet dropping by node, channel, and random rate.
 */
bool shouldDrop(const meshtastic_MeshPacket *p);

/**
 * Called from Router::handleReceived() — AFTER perhapsDecode() succeeds,
 * BEFORE MeshModule::callModules().
 *
 * Modifies the decoded payload in-place. Because re-encryption happens later
 * in Router::send() → perhapsEncode(), any change to p->decoded.payload is
 * automatically re-encrypted when the packet is relayed.
 *
 * Only acts on packets NOT from us (relay path). Own transmissions are
 * not modified.
 *
 * Implements: decrypt-modify-re-encrypt MitM pipeline.
 */
void transformPacket(meshtastic_MeshPacket *p);

/**
 * Called from NextHopRouter::perhapsRebroadcast() — AFTER the copy is made
 * (`tosend = allocCopy(*p)`), on the copy only.
 *
 * Modifies tosend->hop_limit before the packet is queued for transmission.
 * When EVIL_HOP_MAX: forces to 7.
 * When EVIL_HOP_KILL: forces to 0 (packet dies after one more relay).
 *
 * Implements: hop limit manipulation.
 */
void manipulateHopLimit(meshtastic_MeshPacket *tosend);

/**
 * Trigger a NodeInfo flood: send state.flood_count NodeInfo packets from
 * random spoofed node IDs. Each packet has a random long name.
 * If state.flood_keys, each also carries a fake 32-byte public key.
 *
 * Must be called with EVIL_ALLOW_FROM_OVERRIDE enabled — otherwise from node
 * ID cannot be spoofed.
 *
 * Note: blocks for ~300ms × flood_count (yields via delay() in FreeRTOS).
 *
 * Implements: NodeDB exhaustion attack.
 */
void floodNodeInfo();

} // namespace EvilNode

#endif // EVIL_NODE
