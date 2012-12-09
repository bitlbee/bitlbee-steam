/*
 * Copyright 2012 James Geboski <jgeboski@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>

#include "steam-util.h"

#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
    g_slist_foreach(list, (GFunc) free_func, NULL);
    g_slist_free(list);
}
#endif

void steam_util_buddy_status(SteamData *sd, const gchar *steamid,
                             SteamState state, const gchar *game)
{
    bee_user_t    *bu;
    irc_channel_t *ircc;
    irc_user_t    *ircu;

    gint   f;
    gchar *m;

    g_return_if_fail(sd      != NULL);
    g_return_if_fail(steamid != NULL);

    bu = bee_user_by_handle(sd->ic->bee, sd->ic, steamid);

    if (bu == NULL)
        return;

    if (state == STEAM_STATE_OFFLINE) {
        imcb_buddy_status(sd->ic, steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_state_str(state);

    if (state != STEAM_STATE_ONLINE)
        f |= OPT_AWAY;

    imcb_buddy_status(sd->ic, steamid, f, m, game);

    if (sd->show_playing == STEAM_CHANNEL_USER_OFF)
        return;

    ircu = bu->ui_data;
    ircc = ircu->irc->default_channel;

    if (game != NULL)
        irc_channel_user_set_mode(ircc, ircu, sd->show_playing);
}

gint steam_util_user_mode(gchar *mode)
{
    if (mode == NULL)
        return STEAM_CHANNEL_USER_OFF;

    if (is_bool(mode) && !bool2int(mode))
        return STEAM_CHANNEL_USER_OFF;

    switch (mode[0]) {
    case '@':
        return IRC_CHANNEL_USER_OP;

    case '%':
        return IRC_CHANNEL_USER_HALFOP;

    case '+':
        return IRC_CHANNEL_USER_VOICE;

    default:
        return IRC_CHANNEL_USER_NONE;
    }
}

gboolean steam_util_xt_node(struct xt_node *xr, const gchar *name,
                            struct xt_node **xn)
{
    *xn = xt_find_node(xr->children, name);
    return (*xn != NULL);
}
