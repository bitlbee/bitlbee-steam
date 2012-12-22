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

#include "steam.h"
#include "steam-api.h"
#include "xmltree.h"

#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func);
#endif

void steam_util_smtoss(SteamMessage *sm, SteamSummary *ss);

gint steam_util_user_mode(gchar *mode);

gboolean steam_util_xn_node(struct xt_node *xr, const gchar *name,
                            struct xt_node **xn);

gboolean steam_util_xn_int(struct xt_node *xr, const gchar *name, gint *i);

gboolean steam_util_xn_str(struct xt_node *xn, const gchar *name,
                           const gchar **str);

gboolean steam_util_xn_cmp(struct xt_node *xr, const gchar *name,
                           const gchar *match, const gchar **str);

#endif /* _STEAM_UTIL_H */
