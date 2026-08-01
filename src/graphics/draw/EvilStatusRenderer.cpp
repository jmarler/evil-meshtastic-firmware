#include "configuration.h"
#ifdef EVIL_NODE
#if HAS_SCREEN

#include "EvilStatusRenderer.h"
#include "UIRenderer.h"
#include "graphics/SharedUIDisplay.h"
#include "graphics/ScreenFonts.h"
#include "mesh/EvilNode.h"
#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>
#include <string.h>

namespace graphics
{
namespace EvilStatusRenderer
{

void drawEvilStatusFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y)
{
    display->clear();
    display->setTextAlignment(TEXT_ALIGN_LEFT);
    display->setFont(FONT_SMALL);

    graphics::drawCommonHeader(display, x, y, "EVIL NODE");

    const int *tp = getTextPositions(display);
    int line = 1;

    // --- Row 1: Transform mode ---
    static const char *xfm_names[] = { "off", "ROT13", "Rev", "Sfx" };
    uint8_t xfm = EvilNode::state.transform;
    const char *xfm_name = xfm <= 3 ? xfm_names[xfm] : "?";

    // --- Row 1 right: Hop mode ---
    static const char *hop_names[] = { "nrm", "MAX", "KILL" };
    uint8_t hop = EvilNode::state.hop_mode;
    const char *hop_name = hop <= 2 ? hop_names[hop] : "?";

    char row1[32];
    snprintf(row1, sizeof(row1), "xfm:%-5s  hop:%s", xfm_name, hop_name);
    display->drawString(x, tp[line++], row1);

    // --- Row 2: Drop rate + channel ---
    char row2[32];
    uint32_t dr = EvilNode::state.drop_rate;
    uint8_t dc = EvilNode::state.drop_channel;
    if (dc == 255) {
        snprintf(row2, sizeof(row2), "drop:%3d%%  ch:off", dr);
    } else {
        snprintf(row2, sizeof(row2), "drop:%3d%%  ch:%d", dr, dc);
    }
    display->drawString(x, tp[line++], row2);

    // --- Row 3: Flood count / keys ---
    char row3[32];
    uint32_t fc = EvilNode::state.flood_count;
    bool fk = EvilNode::state.flood_keys;
    snprintf(row3, sizeof(row3), "flood cnt:%-3d key:%c", fc, fk ? 'Y' : 'N');
    display->drawString(x, tp[line++], row3);

    // --- Row 4: Drop node (abbreviated hex if non-zero) ---
    char row4[32];
    uint32_t dn = EvilNode::state.drop_node;
    if (dn != 0) {
        snprintf(row4, sizeof(row4), "node:!%08x", dn);
    } else {
        snprintf(row4, sizeof(row4), "node:off");
    }
    display->drawString(x, tp[line++], row4);

    // --- Row 5: Access mode ---
    display->drawString(x, tp[line++], "ctrl:local-only");
}

} // namespace EvilStatusRenderer
} // namespace graphics

#endif // HAS_SCREEN
#endif // EVIL_NODE
