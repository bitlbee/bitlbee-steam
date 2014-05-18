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
 * @param val  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_val(const json_value *json, const gchar *name,
                        json_type type, json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val  != NULL, FALSE);

    *val = json_o_get(json, name);

    return ((*val != NULL) && ((*val)->type == type));
}

/**
 * Gets a boolean value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_bool(const json_value *json, const gchar *name)
{
    json_value *jv;

    if (!steam_json_val(json, name, json_boolean, &jv))
        return FALSE;

    return jv->u.boolean;
}

/**
 * Gets a integer value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param i    The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_int(const json_value *json, const gchar *name, gint64 *i)
{
    json_value *jv;

    g_return_val_if_fail(i != NULL, FALSE);

    *i = 0;

    if (!steam_json_val(json, name, json_integer, &jv))
        return FALSE;

    *i = jv->u.integer;
    return TRUE;
}

/**
 * Gets a string value by name from a parent #json_value.
 *
 * @param json The #json_value.
 * @param name The name.
 * @param str  The return location for the value.
 *
 * @return TRUE if the value was found, or FALSE on error.
 **/
gboolean steam_json_str(const json_value *json, const gchar *name,
                        const gchar **str)
{
    json_value *jv;

    g_return_val_if_fail(str != NULL, FALSE);

    *str = NULL;

    if (!steam_json_val(json, name, json_string, &jv) ||
        (jv->u.string.length < 1))
    {
        return FALSE;
    }

    *str = jv->u.string.ptr;
    return TRUE;
}

/**
 * Gets a string value by name from a parent #json_value, and compares
 * the value. This matches case insensitively.
 *
 * @param json  The #json_value.
 * @param name  The name.
 * @param match The string to compare.
 * @param str   The return location for the value.
 *
 * @return TRUE if the value was found and matches, or FALSE on error.
 **/
gboolean steam_json_scmp(const json_value *json, const gchar *name,
                         const gchar *match, const gchar **str)
{
    if (!steam_json_str(json, name, str))
        return FALSE;

    return ((match != NULL) && (g_ascii_strcasecmp(match, *str) == 0));
}

/**
 * Propagates a #GTree of key/value pairs from a #json_value
 * recursively.
 *
 * @param tree The #GTree.
 * @param key  The key name or NULL.
 * @param json The #json_value.
 **/
static void steam_json_tree_prop(GTree *tree, gchar *key,
                                 const json_value *json)
{
    json_value *jv;
    gchar      *val;
    gchar      *cval;
    gsize       i;

    switch (json->type) {
    case json_object:
        for (i = 0; i < json->u.object.length; i++) {
            key = json->u.object.values[i].name;
            jv  = json->u.object.values[i].value;
            steam_json_tree_prop(tree, key, jv);
        }
        return;

    case json_array:
        for (i = 0; i < json->u.array.length; i++) {
            jv = json->u.array.values[i];
            steam_json_tree_prop(tree, key, jv);
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

    cval = g_tree_lookup(tree, key);

    if (cval != NULL) {
        cval = g_strdup_printf("%s,%s", cval, val);
        g_free(val);
        val = cval;
    }

    key = g_strdup(key);
    g_tree_replace(tree, key, val);
}

/**
 * Gets a #GTree of key/value pairs from a #json_value recursively.
 *
 * @param json The #json_value.
 *
 * @return The #GTree of key/value pairs, or NULL on error.
 **/
GTree *steam_json_tree(const json_value *json)
{
    GTree *tree;

    g_return_val_if_fail(json != NULL, NULL);

    tree = g_tree_new_full((GCompareDataFunc) g_ascii_strcasecmp,
                           NULL, g_free, g_free);

    if (json->type == json_object)
        steam_json_tree_prop(tree, NULL, json);

    return tree;
}
