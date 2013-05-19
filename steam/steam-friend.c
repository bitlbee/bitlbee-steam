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
