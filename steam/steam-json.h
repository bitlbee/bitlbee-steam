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

#ifndef _STEAM_JSON_H
#define _STEAM_JSON_H

#include <glib.h>
#include <json_util.h>


/** The #GError codes of the JSON parser. **/
typedef enum _SteamJsonError SteamJsonError;


/**
 * The #GError codes of JSON parser.
 **/
enum _SteamJsonError
{
    STEAM_JSON_ERROR_PARSER
};


#define STEAM_JSON_ERROR steam_json_error_quark()

GQuark steam_json_error_quark(void);

json_value *steam_json_new(const gchar *data, gsize length, GError **err);

gboolean steam_json_val(const json_value *json, const gchar *name,
                        json_type type, json_value **val);

gboolean steam_json_bool(const json_value *json, const gchar *name);

gboolean steam_json_int(const json_value *json, const gchar *name, gint64 *i);

gboolean steam_json_str(const json_value *json, const gchar *name,
                        const gchar **str);

gboolean steam_json_scmp(const json_value *json, const gchar *name,
                         const gchar *match, const gchar **str);

GHashTable *steam_json_table(const json_value *json);

#endif /* _STEAM_JSON_H */
