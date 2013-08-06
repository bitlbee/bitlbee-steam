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

#ifndef _STEAM_JSON_H
#define _STEAM_JSON_H

#include <glib.h>
#include <json_util.h>

typedef enum _SteamJsonError SteamJsonError;

enum _SteamJsonError
{
    STEAM_JSON_ERROR_PARSER
};

#define STEAM_JSON_ERROR steam_json_error_quark()

GQuark steam_json_error_quark(void);

json_value *steam_json_new(const gchar *data, GError **err);

gboolean steam_json_val(json_value *json, const gchar *name, json_type type,
                        json_value **val);

gboolean steam_json_bool(json_value *json, const gchar *name);

gboolean steam_json_int(json_value *json, const gchar *name, gint64 *i);

gboolean steam_json_str(json_value *json, const gchar *name, const gchar **str);

gboolean steam_json_scmp(json_value *json, const gchar *name,
                         const gchar *match, const gchar **str);

#endif /* _STEAM_JSON_H */
