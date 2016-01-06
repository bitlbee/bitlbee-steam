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

#include <inttypes.h>
#include <string.h>

#include "steam-json.h"

/**
 * Gets the error domain for the JSON parser.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark
steam_json_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("steam-json-error-quark");
    }

    return q;
}

/**
 * Creates a new #json_value from JSON data. The returned #json_value
 * should be freed with #json_value_free() when no longer needed.
 *
 * @param data The JSON data.
 * @param length The length of the JSON data.
 * @param err The return location for a GError or NULL.
 *
 * @return The #json_value or NULL on error.
 **/
json_value *
steam_json_new(const gchar *data, gsize length, GError **err)
{
    gchar *estr;
    json_settings js;
    json_value *json;

    memset(&js, 0, sizeof js);
    estr = g_new0(gchar, json_error_max);
    json = json_parse_ex(&js, data, length, estr);

    if ((json != NULL) && (strlen(estr) < 1)) {
        g_free(estr);
        return json;
    }

    g_set_error(err, STEAM_JSON_ERROR, STEAM_JSON_ERROR_PARSER,
                "Parser: %s", estr);

    g_free(estr);
    return NULL;
}

/**
 * Gets the string representation of a #json_value. The returned string
 * should be freed with #g_free() when no longer needed.
 *
 * @param json The #json_value.
 *
 * @return The resulting string, or NULL on error.
 **/
gchar *
steam_json_valstr(const json_value *json)
{
    g_return_val_if_fail(json != NULL, NULL);

    switch (json->type) {
    case json_integer:
        return g_strdup_printf("%" PRId64, json->u.integer);

    case json_double:
        return g_strdup_printf("%f", json->u.dbl);

    case json_string:
        return g_strdup(json->u.string.ptr);

    case json_boolean:
        return g_strdup(json->u.boolean ? "true" : "false");

    case json_null:
        return g_strdup("null");

    default:
        return NULL;
    }
}

/**
 * Gets a #json_value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 *
 * @return The json_value if found, otherwise NULL.
 **/
json_value *
steam_json_val(const json_value *json, const gchar *name, json_type type)
{
    json_value *val;

    if (!steam_json_val_chk(json, name, type, &val)) {
        return NULL;
    }

    return val;
}

/**
 * Gets a #json_value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 * @param val The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean
steam_json_val_chk(const json_value *json, const gchar *name,
                   json_type type, json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val != NULL, FALSE);

    *val = json_o_get(json, name);

    if ((*val == NULL) || ((*val)->type != type)) {
        *val = NULL;
        return FALSE;
    }

    return TRUE;
}

/**
 * Gets an array by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 *
 * @return The #json_value if found, otherwise NULL.
 **/
json_value *
steam_json_array(const json_value *json, const gchar *name)
{
    json_value *val;

    if (!steam_json_array_chk(json, name, &val)) {
        return NULL;
    }

    return val;
}

/**
 * Gets an array by name from a parent #json_value, and checks for its
 * existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 * @param val The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean
steam_json_array_chk(const json_value *json, const gchar *name,
                     json_value **val)
{
    return steam_json_val_chk(json, name, json_array, val);
}

/**
 * Gets a boolean value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 *
 * @return The boolean value if found, otherwise FALSE.
 **/
gboolean
steam_json_bool(const json_value *json, const gchar *name)
{
    gboolean val;

    if (!steam_json_bool_chk(json, name, &val)) {
        return FALSE;
    }

    return val;
}

/**
 * Gets a boolean value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val The return location for the value.
 *
 * @return The boolean value if found, otherwise FALSE.
 **/
gboolean
steam_json_bool_chk(const json_value *json, const gchar *name, gboolean *val)
{
    json_value *jv;

    g_return_val_if_fail(val != NULL, FALSE);

    if (!steam_json_val_chk(json, name, json_boolean, &jv)) {
        *val = FALSE;
        return FALSE;
    }

    *val = jv->u.boolean;
    return TRUE;
}

/**
 * Gets a integer value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 *
 * @return The integer value if found, otherwise 0.
 **/
gint64
steam_json_int(const json_value *json, const gchar *name)
{
    gint64 val;

    if (!steam_json_int_chk(json, name, &val)) {
        return 0;
    }

    return val;
}

/**
 * Gets a integer value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean
steam_json_int_chk(const json_value *json, const gchar *name, gint64 *val)
{
    json_value *jv;

    g_return_val_if_fail(val != NULL, FALSE);

    if (!steam_json_val_chk(json, name, json_integer, &jv)) {
        *val = 0;
        return FALSE;
    }

    *val = jv->u.integer;
    return TRUE;
}

/**
 * Gets a string value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 *
 * @return The string value if found, otherwise NULL.
 **/
const gchar *
steam_json_str(const json_value *json, const gchar *name)
{
    const gchar *val;

    if (!steam_json_str_chk(json, name, &val)) {
        return NULL;
    }

    return val;
}

/**
 * Gets a string value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean
steam_json_str_chk(const json_value *json, const gchar *name,
                   const gchar **val)
{
    json_value *jv;

    g_return_val_if_fail(val != NULL, FALSE);

    if (!steam_json_val_chk(json, name, json_string, &jv)) {
        *val = NULL;
        return FALSE;
    }

    *val = jv->u.string.ptr;
    return TRUE;
}
