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

gboolean steam_util_json_val(json_value *json, const gchar *name,
                             json_type type, json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val  != NULL, FALSE);

    *val = json_o_get(json, name);

    if (*val == NULL)
        return FALSE;

    return ((*val)->type == type);
}

gboolean steam_util_json_int(json_value *json, const gchar *name, gint64 *i)
{
    json_value *jv;

    g_return_val_if_fail(i != NULL, FALSE);

    *i = 0;

    if (!steam_util_json_val(json, name, json_integer, &jv) || (jv == NULL))
        return FALSE;

    *i = jv->u.integer;
    return TRUE;
}

gboolean steam_util_json_str(json_value *json, const gchar *name,
                             const gchar **str)
{
    json_value *jv;

    g_return_val_if_fail(str != NULL, FALSE);

    *str = NULL;

    if (!steam_util_json_val(json, name, json_string, &jv))
        return FALSE;

    if ((jv == NULL) && (jv->u.string.length < 1))
        return FALSE;

    *str = jv->u.string.ptr;
    return TRUE;
}

gboolean steam_util_json_scmp(json_value *json, const gchar *name,
                              const gchar *match, const gchar **str)
{
    return (steam_util_json_str(json, name, str) && !g_strcmp0(match, *str));
}

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
