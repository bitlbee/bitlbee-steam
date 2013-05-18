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

#include <stdarg.h>
#include <string.h>

#include "steam-glib.h"

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
