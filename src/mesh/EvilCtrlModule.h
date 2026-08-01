/**
 * EvilCtrlModule.h — Runtime control interface for evil-node features.
 *
 * Listens for EvilCtrlMsg packets addressed to the local node on
 * PRIVATE_APP (portnum 256).  Packets are delivered locally by
 * Router::sendLocal() without any radio transmission.
 *
 * The Python tool (tools/evil_ctrl.py) and the mobile apps send these
 * packets via the serial/BLE API to change evil behaviour at runtime,
 * replacing the previous compile-time-only approach.
 *
 * Project: Evil Meshtastic — DefCon 2026 HRV security research
 */

#pragma once

#ifdef EVIL_NODE

#include "MeshModule.h"

class EvilCtrlModule : public MeshModule
{
  public:
    EvilCtrlModule();

  protected:
    bool wantPacket(const meshtastic_MeshPacket *p) override;
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;
};

extern EvilCtrlModule *evilCtrlModule;

#endif // EVIL_NODE
