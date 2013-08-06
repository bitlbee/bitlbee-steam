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

#include <string.h>

#include "steam-json.h"

GQuark steam_json_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-json-error-quark");

    return q;
}

json_value *steam_json_new(const gchar *data, GError **err)
{
    json_value    *json;
    json_settings  js;
    gchar          estr[128];

    memset(&js, 0, sizeof js);
    json = json_parse_ex(&js, data, estr);

    if ((json != NULL) || (err == NULL))
        return json;

    g_set_error(err, STEAM_JSON_ERROR, STEAM_JSON_ERROR_PARSER,
                "Parser: %s", estr);
    return NULL;
}

gboolean steam_json_val(json_value *json, const gchar *name, json_type type,
                        json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val  != NULL, FALSE);

    *val = json_o_get(json, name);

    return ((*val != NULL) && ((*val)->type == type));
}

gboolean steam_json_bool(json_value *json, const gchar *name)
{
    json_value *jv;

    if (!steam_json_val(json, name, json_boolean, &jv))
        return FALSE;

    return jv->u.boolean;
}

gboolean steam_json_int(json_value *json, const gchar *name, gint64 *i)
{
    json_value *jv;

    g_return_val_if_fail(i != NULL, FALSE);

    *i = 0;

    if (!steam_json_val(json, name, json_integer, &jv))
        return FALSE;

    *i = jv->u.integer;
    return TRUE;
}

gboolean steam_json_str(json_value *json, const gchar *name, const gchar **str)
{
    json_value *jv;

    g_return_val_if_fail(str != NULL, FALSE);

    *str = NULL;

    if (!steam_json_val(json, name, json_string, &jv) ||
        (jv->u.string.length < 1))
        return FALSE;

    *str = jv->u.string.ptr;
    return TRUE;
}

gboolean steam_json_scmp(json_value *json, const gchar *name,
                         const gchar *match, const gchar **str)
{
    if (!steam_json_str(json, name, str))
        return FALSE;

    return ((match != NULL) && (g_ascii_strcasecmp(match, *str) == 0));
}
