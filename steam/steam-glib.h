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

#ifndef _STEAM_GLIB_H
#define _STEAM_GLIB_H

#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 16, 0)
void g_prefix_error(GError **err, const gchar *format, ...);

int g_strcmp0(const char *str1, const char *str2);
#endif

#if !GLIB_CHECK_VERSION(2, 28, 0)
void g_slist_free_full(GSList *list, GDestroyNotify free_func);
#endif

#if !GLIB_CHECK_VERSION(2, 32, 0)
void g_hash_table_add(GHashTable *hash_table, gpointer key);

gboolean g_hash_table_contains(GHashTable *hash_table, gconstpointer key);
#endif

#endif /* _STEAM_GLIB_H */
