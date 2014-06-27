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

#include <string.h>

#include "steam-json.h"

/**
 * Gets the error domain for the JSON parser.
 *
 * @return The #GQuark of the error domain.
 **/
GQuark steam_json_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-json-error-quark");

    return q;
}

/**
 * Creates a new #json_value from JSON data. The returned #json_value
 * should be freed with #json_value_free() when no longer needed.
 *
 * @param data   The JSON data.
 * @param length The length of the JSON data.
 * @param err    The return location for a GError or NULL.
 *
 * @return The #json_value or NULL on error.
 **/
json_value *steam_json_new(const gchar *data, gsize length, GError **err)
{
    json_value    *json;
    json_settings  js;
    gchar         *estr;

    memset(&js, 0, sizeof js);

#ifdef json_error_max
    estr = g_new0(gchar, json_error_max);
    json = json_parse_ex(&js, data, length, estr);
#else
    estr = g_new0(gchar, 128);
    json = json_parse_ex(&js, data, estr);
#endif

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
 * Gets a #json_value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 *
 * @return The json_value if found, otherwise NULL.
 **/
json_value *steam_json_val(const json_value *json, const gchar *name,
                           json_type type)
{
    json_value *val;

    if (!steam_json_val_chk(json, name, type, &val))
        return NULL;

    return val;
}

/**
 * Gets a #json_value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 * @param val  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_val_chk(const json_value *json, const gchar *name,
                            json_type type, json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val  != NULL, FALSE);

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
json_value *steam_json_array(const json_value *json, const gchar *name)
{
    json_value *val;

    if (!steam_json_array_chk(json, name, &val))
        return NULL;

    return val;
}

/**
 * Gets an array by name from a parent #json_value, and checks for its
 * existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param type The #json_type.
 * @param val  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_array_chk(const json_value *json, const gchar *name,
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
gboolean steam_json_bool(const json_value *json, const gchar *name)
{
    gboolean val;

    if (!steam_json_bool_chk(json, name, &val))
        return FALSE;

    return val;
}

/**
 * Gets a boolean value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val  The return location for the value.
 *
 * @return The boolean value if found, otherwise FALSE.
 **/
gboolean steam_json_bool_chk(const json_value *json, const gchar *name,
                             gboolean *val)
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
gint64 steam_json_int(const json_value *json, const gchar *name)
{
    gint64 val;

    if (!steam_json_int_chk(json, name, &val))
        return 0;

    return val;
}

/**
 * Gets a integer value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_int_chk(const json_value *json, const gchar *name,
                            gint64 *val)
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
const gchar *steam_json_str(const json_value *json, const gchar *name)
{
    const gchar *val;

    if (!steam_json_str_chk(json, name, &val))
        return NULL;

    return val;
}

/**
 * Gets a string value by name from a parent #json_value, and checks
 * for its existence and type.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param val  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_str_chk(const json_value *json, const gchar *name,
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

/**
 * Fills a #GHashTable with key/value pairs from a #json_value
 * recursively.
 *
 * @param table The #GHashTable.
 * @param key   The key name or NULL.
 * @param json  The #json_value.
 **/
static void steam_json_table_fill(GHashTable *table, gchar *key,
                                  const json_value *json)
{
    json_value *jv;
    gchar      *val;
    gchar      *lval;
    gsize       i;

    switch (json->type) {
    case json_object:
        for (i = 0; i < json->u.object.length; i++) {
            key = json->u.object.values[i].name;
            jv  = json->u.object.values[i].value;
            steam_json_table_fill(table, key, jv);
        }
        return;

    case json_array:
        for (i = 0; i < json->u.array.length; i++) {
            jv = json->u.array.values[i];
            steam_json_table_fill(table, key, jv);
        }
        return;

    case json_integer:
#if json_error_max
        val = g_strdup_printf("%ld", json->u.integer);
#else
        val = g_strdup_printf("%lld", json->u.integer);
#endif
        break;

    case json_double:
        val = g_strdup_printf("%f", json->u.dbl);
        break;

    case json_string:
        val = g_strdup(json->u.string.ptr);
        break;

    case json_boolean:
        val = g_strdup(json->u.boolean ? "true" : "false");
        break;

    case json_null:
        val = g_strdup("null");
        break;

    default:
        return;
    }

    if (key == NULL)
        return;

    lval = g_hash_table_lookup(table, key);

    if (lval != NULL) {
        lval = g_strdup_printf("%s,%s", lval, val);
        g_free(val);
        val = lval;
    }

    key = g_strdup(key);
    g_hash_table_replace(table, key, val);
}

/**
 * Gets a #GHashTable of key/value pairs from a #json_value recursively.
 *
 * @param json The #json_value.
 *
 * @return The #GHashTable of key/value pairs, or NULL on error.
 **/
GHashTable *steam_json_table(const json_value *json)
{
    GHashTable *table;

    g_return_val_if_fail(json != NULL, NULL);

    table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

    if (json->type == json_object)
        steam_json_table_fill(table, NULL, json);

    return table;
}
