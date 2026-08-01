/**
 * EvilCtrlModule.cpp — Runtime control interface for evil-node features.
 *
 * Receives EvilCtrlMsg packets on PRIVATE_APP (portnum 256) addressed to
 * this node and updates EvilNode::state accordingly.  No radio TX occurs —
 * Router::sendLocal() delivers these packets directly to the module
 * dispatch loop when dest == getNodeNum().
 *
 * Project: Evil Meshtastic — DefCon 2026 HRV security research
 */

#ifdef EVIL_NODE

#include "EvilCtrlModule.h"
#include "EvilNode.h"
#include "MeshService.h"
#include "MeshTypes.h"
#include "NodeDB.h"
#include "Router.h"
#include "configuration.h"
#include "mesh/generated/meshtastic/evil_control.pb.h"
#include "mesh/generated/meshtastic/portnums.pb.h"
#include <pb_decode.h>
#include <string.h>

EvilCtrlModule *evilCtrlModule;

EvilCtrlModule::EvilCtrlModule() : MeshModule("EvilCtrl")
{
}

bool EvilCtrlModule::wantPacket(const meshtastic_MeshPacket *p)
{
    // Only handle decoded packets addressed to us on PRIVATE_APP
    return p->which_payload_variant == meshtastic_MeshPacket_decoded_tag &&
           p->decoded.portnum == meshtastic_PortNum_PRIVATE_APP &&
           isToUs(p);
}

ProcessMessage EvilCtrlModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    // Decode the EvilCtrlMsg protobuf from the packet payload
    meshtastic_EvilCtrlMsg msg = meshtastic_EvilCtrlMsg_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(mp.decoded.payload.bytes, mp.decoded.payload.size);
    if (!pb_decode(&stream, meshtastic_EvilCtrlMsg_fields, &msg)) {
        LOG_WARN("EvilCtrl: failed to decode EvilCtrlMsg");
        return ProcessMessage::STOP;
    }

    // --- local-only access control -------------------------------------------
    // Only accept packets from the local device (serial/BLE/USB, not radio).
    // isFromUs() returns true when from==0 (locally injected) or
    // from==myNodeNum (local client with EVIL_ALLOW_FROM_OVERRIDE).
    if (!isFromUs(&mp)) {
        LOG_WARN("EvilCtrl: rejected non-local packet from 0x%08x", mp.from);
        return ProcessMessage::STOP;
    }

    LOG_INFO("EvilCtrl: local packet accepted — processing control message");

    // --- state updates (skipped for pure status queries) --------------------
    // Proto3 encodes zero-value fields as absent on the wire; the decoder
    // restores them to 0.  A get_status=true packet has all state fields at
    // their zero default — applying those would silently reset all settings.
    // Solution: status queries only read state; they never write it.
    if (!msg.get_status) {
        // --- transform --------------------------------------------------
        if (msg.transform <= 3) {
            EvilNode::state.transform = (uint8_t)msg.transform;
            LOG_INFO("EvilCtrl: transform=%d", EvilNode::state.transform);
        }
        if (msg.suffix[0] != '\0') {
            strncpy(EvilNode::state.suffix, msg.suffix, sizeof(EvilNode::state.suffix) - 1);
            EvilNode::state.suffix[sizeof(EvilNode::state.suffix) - 1] = '\0';
            LOG_INFO("EvilCtrl: suffix='%s'", EvilNode::state.suffix);
        }

        // --- packet drop ------------------------------------------------
        if (msg.drop_rate <= 100) {
            EvilNode::state.drop_rate = msg.drop_rate;
            LOG_INFO("EvilCtrl: drop_rate=%d%%", EvilNode::state.drop_rate);
        }
        EvilNode::state.drop_node    = msg.drop_node;
        EvilNode::state.drop_channel = (msg.drop_channel == 0 && msg.drop_rate == 0 && msg.drop_node == 0)
                                           ? EvilNode::state.drop_channel
                                           : (uint8_t)msg.drop_channel;

        // --- hop mode ---------------------------------------------------
        if (msg.hop_mode <= 2) {
            EvilNode::state.hop_mode = (uint8_t)msg.hop_mode;
            LOG_INFO("EvilCtrl: hop_mode=%d", EvilNode::state.hop_mode);
        }

        // --- flood ------------------------------------------------------
        if (msg.flood_count > 0 && msg.flood_count <= 200)
            EvilNode::state.flood_count = msg.flood_count;
        EvilNode::state.flood_keys = msg.flood_keys;

        if (msg.flood) {
#ifdef EVIL_ALLOW_FROM_OVERRIDE
            LOG_INFO("EvilCtrl: triggering NodeInfo flood (count=%d, keys=%d)",
                     EvilNode::state.flood_count, EvilNode::state.flood_keys);
            EvilNode::floodNodeInfo();
#else
            LOG_WARN("EvilCtrl: flood requested but EVIL_ALLOW_FROM_OVERRIDE not enabled");
#endif
        }
    }

    // --- status reply -------------------------------------------------------
    if (msg.get_status) {
        LOG_INFO("EvilCtrl: status -- transform=%d drop_rate=%d drop_node=0x%08x "
                 "drop_channel=%d hop_mode=%d flood_count=%d flood_keys=%d",
                 EvilNode::state.transform,
                 EvilNode::state.drop_rate,
                 EvilNode::state.drop_node,
                 EvilNode::state.drop_channel,
                 EvilNode::state.hop_mode,
                 EvilNode::state.flood_count,
                 EvilNode::state.flood_keys);

        // Send a reply packet back to the connected client (phone / evil_ctrl.py).
        // Uses service->sendToPhone() — delivered over the Meshtastic PacketAPI USB
        // interface, which is separate from Arduino Serial and works on the production
        // firmware (CDC_ON_BOOT=0) without any USB mode changes.
        meshtastic_EvilCtrlMsg reply = meshtastic_EvilCtrlMsg_init_zero;
        reply.is_reply     = true;
        reply.transform    = EvilNode::state.transform;
        reply.drop_rate    = EvilNode::state.drop_rate;
        reply.drop_node    = EvilNode::state.drop_node;
        reply.drop_channel = EvilNode::state.drop_channel;
        reply.hop_mode     = EvilNode::state.hop_mode;
        reply.flood_count  = EvilNode::state.flood_count;
        reply.flood_keys   = EvilNode::state.flood_keys;
        strncpy(reply.suffix, EvilNode::state.suffix, sizeof(reply.suffix) - 1);

        meshtastic_MeshPacket *rp = packetPool.allocZeroed();
        if (rp) {
            rp->which_payload_variant = meshtastic_MeshPacket_decoded_tag;
            rp->from     = nodeDB->getNodeNum();
            rp->to       = nodeDB->getNodeNum();
            rp->id       = generatePacketId();
            rp->channel  = 0;
            rp->hop_limit = 0;
            rp->decoded.portnum = meshtastic_PortNum_PRIVATE_APP;
            rp->decoded.payload.size = pb_encode_to_bytes(
                rp->decoded.payload.bytes, sizeof(rp->decoded.payload.bytes),
                &meshtastic_EvilCtrlMsg_msg, &reply);
            if (rp->decoded.payload.size > 0) {
                LOG_INFO("EvilCtrl: sending status reply (%d bytes)", rp->decoded.payload.size);
                service->sendToPhone(rp);
            } else {
                LOG_WARN("EvilCtrl: status reply encode failed");
                packetPool.release(rp);
            }
        } else {
            LOG_WARN("EvilCtrl: packet pool exhausted, status reply dropped");
        }
    }

    return ProcessMessage::STOP;
}

#endif // EVIL_NODE
