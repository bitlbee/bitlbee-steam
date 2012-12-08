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

#ifndef _STEAM_UTIL_H
#define _STEAM_UTIL_H

#include <bitlbee.h>

#include "steam-api.h"
#include "xmltree.h"

#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func);
#endif

void steam_util_buddy_status_ss(struct im_connection *ic, SteamSummary *ss);

void steam_util_buddy_status_sm(struct im_connection *ic, SteamMessage *sm);

gboolean steam_util_xt_node(struct xt_node *xr, const gchar *name,
                            struct xt_node **xn);

#endif /* _STEAM_UTIL_H */
