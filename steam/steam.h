/*
 * Copyright 2012-2016 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_H_
#define _STEAM_H_

/**
 * SECTION:steam
 * @section_id: steam-plugin
 * @short_description: <filename>steam.h</filename>
 * @title: Steam Plugin
 *
 * The Steam BitlBee #prpl.
 */

#include <bitlbee.h>

#include "steam-api.h"
#include "steam-glib.h"

typedef struct _SteamData SteamData;

/**
 * SteamData:
 * @api: The #SteamApi.
 * @ic: The #im_connection.
 * @game_status: #TRUE to print game statues, otherwise #FALSE.
 *
 * The main data structure for the plugin.
 */
struct _SteamData
{
    SteamApi *api;
    struct im_connection *ic;
    gboolean game_status;
};

/**
 * steam_data_new:
 * @acc: The #account.
 *
 * Creates a new #SteamData. The returned #SteamData should be freed
 * with #steam_data_free() when no longer needed.
 *
 * Returns: The #SteamData.
 */
SteamData *
steam_data_new(account_t *acc);

/**
 * steam_data_free:
 * @sata: The #SteamData.
 *
 * Frees all memory used by the #SteamData.
 */
void
steam_data_free(SteamData *sata);

#endif /* _STEAM_H_ */
