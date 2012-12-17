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

void steam_util_buddy_status(SteamData *sd, SteamSummary *ss)
{
    bee_user_t    *bu;
    irc_channel_t *ircc;
    irc_user_t    *ircu;

    gint   f;
    gchar *m;

    g_return_if_fail(sd != NULL);
    g_return_if_fail(ss != NULL);

    bu = bee_user_by_handle(sd->ic->bee, sd->ic, ss->steamid);

    if (bu == NULL)
        return;

    /* Check rather than freeing/reallocating */
    if (g_strcmp0(bu->nick, ss->nick))
        imcb_buddy_nick_hint(sd->ic, ss->steamid, ss->nick);

    imcb_rename_buddy(sd->ic, ss->steamid, ss->fullname);

    if (ss->state == STEAM_STATE_OFFLINE) {
        imcb_buddy_status(sd->ic, ss->steamid, 0, NULL, NULL);
        return;
    }

    f = OPT_LOGGED_IN;
    m = steam_state_str(ss->state);

    if (ss->state != STEAM_STATE_ONLINE)
        f |= OPT_AWAY;

    imcb_buddy_status(sd->ic, ss->steamid, f, m, ss->game);

    if (!sd->extra_info)
        return;

    ircu = bu->ui_data;
    ircc = ircu->irc->default_channel;

    if (ss->game != NULL)
        irc_channel_user_set_mode(ircc, ircu, sd->show_playing);
}

gint steam_util_user_mode(gchar *mode)
{
    if (mode == NULL)
        return IRC_CHANNEL_USER_NONE;

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

gboolean steam_util_xn_node(struct xt_node *xr, const gchar *name,
                            struct xt_node **xn)
{
    struct xt_node *xe;

    g_return_val_if_fail(xr   != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);

    *xn = xt_find_node(xr->children, name);
    return (*xn != NULL);
}

gboolean steam_util_xn_text(struct xt_node *xr, const gchar *name,
                            gchar **text)
{
    struct xt_node *xn;

    g_return_val_if_fail(name != NULL, FALSE);

    *text = NULL;

    if (xr == NULL)
        return FALSE;

    if (!steam_util_xn_node(xr, name, &xn))
        return FALSE;

    *text = xn->text;
    return (*text != NULL);
}

gboolean steam_util_xn_cmp(struct xt_node *xr, const gchar *name,
                           const gchar *match, gchar **text)
{
    if (!steam_util_xn_text(xr, name, text))
        return FALSE;

    if (g_strcmp0(*text, match))
        return FALSE;

    return TRUE;
}
