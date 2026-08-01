#pragma once

#ifdef EVIL_NODE

#include <OLEDDisplay.h>
#include <OLEDDisplayUi.h>

namespace graphics
{

class Screen;

namespace EvilStatusRenderer
{

/**
 * OLED status page for evil-node firmware.
 * Replaces the clock frame in the !DISPLAY_CLOCK_FRAME variant.
 * Displays current EvilNode::state at a glance.
 *
 * Layout (128x64):
 *   Header (inverted):  EVIL NODE
 *   Line 1:  xfm: ROT13    hop: max
 *   Line 2:  drop: 30%     ch: 0
 *   Line 3:  flood: off    cnt: 200
 */
void drawEvilStatusFrame(OLEDDisplay *display, OLEDDisplayUiState *state, int16_t x, int16_t y);

} // namespace EvilStatusRenderer

} // namespace graphics

#endif // EVIL_NODE
