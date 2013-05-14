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

#ifndef _STEAM_UTIL_H
#define _STEAM_UTIL_H

#include <stdarg.h>

#include <bitlbee.h>
#include <json_util.h>

#include "steam.h"
#include "steam-api.h"

gboolean steam_util_json_val(json_value *json, const gchar *name,
                             json_type type, json_value **val);

gboolean steam_util_json_bool(json_value *json, const gchar *name);

gboolean steam_util_json_int(json_value *json, const gchar *name, gint64 *i);

gboolean steam_util_json_str(json_value *json, const gchar *name,
                             const gchar **str);

gboolean steam_util_json_scmp(json_value *json, const gchar *name,
                              const gchar *match, const gchar **str);

gint steam_util_user_mode(gchar *mode);

#ifndef g_prefix_error
void g_prefix_error(GError **err, const gchar *format, ...);
#endif

#ifndef g_slist_free_full
void g_slist_free_full(GSList *list, GDestroyNotify free_func);
#endif

#ifndef g_strcmp0
int g_strcmp0(const char *str1, const char *str2);
#endif

#endif /* _STEAM_UTIL_H */
