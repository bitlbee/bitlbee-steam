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

void steam_util_buddy_status_ss(struct im_connection *ic, SteamSummary *ss)
{
    bee_user_t    *bu;
    irc_channel_t *ircc;
    irc_user_t    *ircu;

    gint   f;
    gchar *m;

    g_return_if_fail(ic != NULL);
    g_return_if_fail(ss != NULL);

    bu = bee_user_by_handle(ic->bee, ic, ss->steamid);

    if (bu == NULL)
        return;

    if (ss->state == STEAM_STATE_OFFLINE) {
        imcb_buddy_status(ic, ss->steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_state_str(ss->state);

    if (ss->state != STEAM_STATE_ONLINE)
        f |= OPT_AWAY;

    imcb_buddy_status(ic, ss->steamid, f, m, ss->game);

    ircu = bu->ui_data;
    ircc = ircu->irc->default_channel;

    if (ss->state == STEAM_STATE_PLAYING)
        irc_channel_user_set_mode(ircc, ircu, IRC_CHANNEL_USER_HALFOP);
}

void steam_util_buddy_status_sm(struct im_connection *ic, SteamMessage *sm)
{
    SteamSummary ss;

    memset(&ss, 0, sizeof ss);

    ss.state   = sm->state;
    ss.steamid = sm->steamid;
    ss.name    = sm->name;

    steam_util_buddy_status_ss(ic, &ss);
}

gboolean steam_util_xt_node(struct xt_node *xr, const gchar *name,
                            struct xt_node **xn)
{
    *xn = xt_find_node(xr->children, name);
    return (*xn != NULL);
}
