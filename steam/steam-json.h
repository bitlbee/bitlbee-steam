/*
 * Copyright 2012-2015 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_JSON_H_
#define _STEAM_JSON_H_

/**
 * SECTION:json
 * @section_id: steam-json
 * @short_description: <filename>steam-json.h</filename>
 * @title: JSON Utilities
 *
 * The JSON utilities.
 */

#include <json_util.h>

#include "steam-glib.h"

/**
 * STEAM_JSON_ERROR:
 *
 * The #GQuark of the domain of JSON errors.
 */
#define STEAM_JSON_ERROR  steam_json_error_quark()

/**
 * SteamJsonError:
 * @STEAM_JSON_ERROR_PARSER: Parser failed.
 *
 * The error codes for the #STEAM_JSON_ERROR domain.
 */
typedef enum
{
    STEAM_JSON_ERROR_PARSER
} SteamJsonError;

/**
 * steam_json_error_quark:
 *
 * Gets the #GQuark of the domain of JSON errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
steam_json_error_quark(void);

/**
 * steam_json_new:
 * @data: The JSON data.
 * @length: The length of the JSON data.
 * @err: The return location for a GError or #NULL.
 *
 * Creates a new #json_value from JSON data. The returned #json_value
 * should be freed with #json_value_free() when no longer needed.
 *
 * Returns: The #json_value or #NULL on error.
 */
json_value *
steam_json_new(const gchar *data, gsize length, GError **err);

/**
 * steam_json_valstr:
 * @json: The #json_value.
 *
 * Gets the string representation of the #json_value. The returned
 * string should be freed with #g_free() when no longer needed.
 *
 * Returns: The resulting string or #NULL on error.
 */
gchar *
steam_json_valstr(const json_value *json);

/**
 * steam_json_val:
 * @json: The #json_value.
 * @name: The name.
 * @type: The #json_type.
 *
 * Gets a #json_value by name from the parent #json_value.
 *
 * Returns: The json_value if found, otherwise #NULL.
 */
json_value *
steam_json_val(const json_value *json, const gchar *name, json_type type);

/**
 * steam_json_val_chk:
 * @json: The #json_value.
 * @name: The name.
 * @type: The #json_type.
 * @val: The return location for the value.
 *
 * Gets a #json_value by name from the parent #json_value, and checks
 * for its existence and type.
 *
 * Returns: #TRUE if the value was found, otherwise #FALSE.
 */
gboolean
steam_json_val_chk(const json_value *json, const gchar *name,
                   json_type type, json_value **val);

/**
 * steam_json_array:
 * @json: The #json_value.
 * @name: The name.
 *
 * Gets an array by name from the parent #json_value.
 *
 * Returns: The #json_value if found, otherwise #NULL.
 */
json_value *
steam_json_array(const json_value *json, const gchar *name);

/**
 * steam_json_array_chk:
 * @json: The #json_value.
 * @name: The name.
 * @type: The #json_type.
 * @val: The return location for the value.
 *
 * Gets an array by name from the parent #json_value, and checks for
 * its existence and type.
 *
 * Returns: #TRUE if the value was found, otherwise #FALSE.
 */
gboolean
steam_json_array_chk(const json_value *json, const gchar *name,
                     json_value **val);

/**
 * steam_json_bool:
 * @json: The #json_value.
 * @name: The name.
 *
 * Gets a boolean value by name from the parent #json_value.
 *
 * Returns: The boolean value if found, otherwise #FALSE.
 */
gboolean
steam_json_bool(const json_value *json, const gchar *name);

/**
 * steam_json_bool_chk:
 * @json: The #json_value.
 * @name: The name.
 * @val: The return location for the value.
 *
 * Gets a boolean value by name from the parent #json_value, and checks
 * for its existence and type.
 *
 * Returns: The boolean value if found, otherwise #FALSE.
 */
gboolean
steam_json_bool_chk(const json_value *json, const gchar *name, gboolean *val);

/**
 * steam_json_int:
 * @json: The #json_value.
 * @name: The name.
 *
 * Gets an integer value by name from the parent #json_value.
 *
 *
 * Returns: The integer value if found, otherwise `0`.
 */
gint64
steam_json_int(const json_value *json, const gchar *name);

/**
 * steam_json_int_chk:
 * @json: The #json_value.
 * @name: The name.
 * @val: The return location for the value.
 *
 * Gets an integer value by name from the parent #json_value, and
 * checks for its existence and type.
 *
 * Returns: #TRUE if the value was found, otherwise #FALSE.
 */
gboolean
steam_json_int_chk(const json_value *json, const gchar *name, gint64 *val);

/**
 * steam_json_str:
 * @json: The #json_value.
 * @name: The name.
 *
 * Gets a string value by name from the parent #json_value.
 *
 * Returns: The string value if found, otherwise #NULL.
 */
const gchar *
steam_json_str(const json_value *json, const gchar *name);

/**
 * steam_json_str_chk:
 * @json: The #json_value.
 * @name: The name.
 * @val: The return location for the value.
 *
 * Gets a string value by name from the parent #json_value, and checks
 * for its existence and type.
 *
 * Returns: #TRUE if the value was found, otherwise #FALSE.
 */
gboolean
steam_json_str_chk(const json_value *json, const gchar *name,
                   const gchar **val);

#endif /* _STEAM_JSON_H_ */
