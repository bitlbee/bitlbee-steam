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

void steam_util_smtoss(SteamMessage *sm, SteamSummary *ss)
{
    g_return_if_fail(sm != NULL);
    g_return_if_fail(ss != NULL);

    memset(ss, 0, sizeof (SteamSummary));

    ss->state   = sm->state;
    ss->steamid = sm->steamid;
    ss->nick    = sm->nick;
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
