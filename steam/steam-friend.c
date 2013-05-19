/*
 * Copyright 2012-2013 James Geboski <jgeboski@gmail.com>
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

#include "steam-friend.h"

SteamFriend *steam_friend_new(bee_user_t *bu)
{
    SteamFriend *frnd;

    frnd = g_new0(SteamFriend, 1);
    frnd->buser = bu;

    return frnd;
}

void steam_friend_free(SteamFriend *frnd)
{
    g_return_if_fail(frnd != NULL);

    g_free(frnd->server);
    g_free(frnd->game);

    g_free(frnd);
}

void steam_friend_update(SteamFriend *frnd, const gchar *game,
                         const gchar *server)
{
    g_return_if_fail(frnd != NULL);

    g_free(frnd->game);
    g_free(frnd->server);

    frnd->game   = g_strdup(game);
    frnd->server = g_strdup(server);
}

void steam_friend_chans_msg(SteamFriend *frnd, const gchar *format, ...)
{
    irc_channel_t *ic;
    irc_user_t    *iu;
    va_list        ap;
    gchar         *str;
    GSList        *l;

    g_return_if_fail(frnd   != NULL);
    g_return_if_fail(format != NULL);

    va_start(ap, format);
    str = g_strdup_vprintf(format, ap);
    va_end(ap);

    iu = frnd->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic = l->data;

        if (irc_channel_has_user(ic, iu) != NULL)
            irc_send_msg(iu, "PRIVMSG", ic->name, str, NULL);
    }

    g_free(str);
}

void steam_friend_chans_umode(SteamFriend *frnd, gint mode)
{
    irc_channel_t      *ic;
    irc_user_t         *iu;
    irc_channel_user_t *icu;
    GSList             *l;

    g_return_if_fail(frnd   != NULL);

    iu = frnd->buser->ui_data;

    for (l = iu->irc->channels; l != NULL; l = l->next) {
        ic  = l->data;
        icu = irc_channel_has_user(ic, iu);

        if (icu != NULL)
            irc_channel_user_set_mode(ic, iu, icu->flags | mode);
    }
}
