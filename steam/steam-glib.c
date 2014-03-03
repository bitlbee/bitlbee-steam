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

#include <stdarg.h>
#include <string.h>

#include "steam-glib.h"

#if !GLIB_CHECK_VERSION(2, 16, 0)
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

int g_strcmp0(const char *str1, const char *str2)
{
    if (str1 == NULL)
        return -(str1 != str2);

    if (str2 == NULL)
        return str1 != str2;

    return strcmp(str1, str2);
}
#endif

#if !GLIB_CHECK_VERSION(2, 28, 0)
void g_slist_free_full(GSList *list, GDestroyNotify free_func)
{
    g_slist_foreach(list, (GFunc) free_func, NULL);
    g_slist_free(list);
}
#endif

#if !GLIB_CHECK_VERSION(2, 32, 0)
void g_hash_table_add(GHashTable *hash_table, gpointer key)
{
    g_hash_table_replace(hash_table, key, key);
}

gboolean g_hash_table_contains(GHashTable *hash_table, gconstpointer key)
{
    return (g_hash_table_lookup(hash_table, key) != NULL);
}
#endif
