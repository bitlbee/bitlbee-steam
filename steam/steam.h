/*
 * Copyright 2012-2014 James Geboski <jgeboski@gmail.com>
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

/** @file **/

#ifndef _STEAM_H
#define _STEAM_H

#include <bitlbee.h>
#include <glib.h>

#include "steam-api.h"


/** The main structure for the plugin. **/
typedef struct _SteamData SteamData;


/**
 * The main structure for the plugin.
 **/
struct _SteamData
{
    SteamApi *api;            /** The #SteamApi. **/
    struct im_connection *ic; /** The #im_connection. **/

    gboolean game_status;     /** The printing of game play statues. **/
    gint     show_playing;    /** The user mode of a #SteamFriend in-game. **/
};


SteamData *steam_data_new(account_t *acc);

void steam_data_free(SteamData *sata);

#endif /* _STEAM_H */
