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

#include "steam-util.h"

gboolean steam_util_json_val(json_value *json, const gchar *name,
                             json_type type, json_value **val)
{
    g_return_val_if_fail(json != NULL, FALSE);
    g_return_val_if_fail(name != NULL, FALSE);
    g_return_val_if_fail(val  != NULL, FALSE);

    *val = json_o_get(json, name);

    return ((*val != NULL) && ((*val)->type == type));
}

gboolean steam_util_json_bool(json_value *json, const gchar *name)
{
    json_value *jv;

    if (!steam_util_json_val(json, name, json_boolean, &jv))
        return FALSE;

    return jv->u.boolean;
}

gboolean steam_util_json_int(json_value *json, const gchar *name, gint64 *i)
{
    json_value *jv;

    g_return_val_if_fail(i != NULL, FALSE);

    *i = 0;

    if (!steam_util_json_val(json, name, json_integer, &jv))
        return FALSE;

    *i = jv->u.integer;
    return TRUE;
}

gboolean steam_util_json_str(json_value *json, const gchar *name,
                             const gchar **str)
{
    json_value *jv;

    g_return_val_if_fail(str != NULL, FALSE);

    *str = NULL;

    if (!steam_util_json_val(json, name, json_string, &jv) ||
        (jv->u.string.length < 1))
        return FALSE;

    *str = jv->u.string.ptr;
    return TRUE;
}

gboolean steam_util_json_scmp(json_value *json, const gchar *name,
                              const gchar *match, const gchar **str)
{
    if (!steam_util_json_str(json, name, str))
        return FALSE;

    return ((match != NULL) && (g_ascii_strcasecmp(match, *str) == 0));
}

gint steam_util_user_mode(gchar *mode)
{
    if (mode == NULL)
        return IRC_CHANNEL_USER_NONE;

    switch (mode[0]) {
    case '@':
        return IRC_CHANNEL_USER_OP;

    case '%':
        return IRC_CHANNEL_USER_HALFOP;

    case '+':
        return IRC_CHANNEL_USER_VOICE;

    default:
        return IRC_CHANNEL_USER_NONE;
    }
}

#ifndef g_prefix_error
/* Compatibility with glib < 2.16 */
void g_prefix_error(GError **err, const gchar *format, ...)
{
    va_list  ap;
    gchar   *p;
    gchar   *m;

    if ((err == NULL) || (*err == NULL))
        return;

    va_start(ap, format);
    p = g_strdup_vprintf(format, ap);
    va_end(ap);

    m = (*err)->message;
    (*err)->message = g_strconcat(p, m, NULL);

    g_free(p);
    g_free(m);
}
#endif

#ifndef g_slist_free_full
/* Compatibility with glib < 2.28 */
void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
    g_slist_foreach(list, (GFunc) free_func, NULL);
    g_slist_free(list);
}
#endif

#ifndef g_strcmp0
/* Compatibility with glib < 2.16 */
int g_strcmp0(const char *str1, const char *str2)
{
    if (str1 == NULL)
        return -(str1 != str2);

    if (str2 == NULL)
        return str1 != str2;

    return strcmp(str1, str2);
}
#endif
