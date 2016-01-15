/*
 * Copyright 2012-2016 James Geboski <jgeboski@gmail.com>
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

#ifndef _STEAM_GLIB_H_
#define _STEAM_GLIB_H_

#include <glib.h>
#include <glib/gprintf.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
static inline void
g_queue_free_full(GQueue *queue, GDestroyNotify free_func)
{
    g_queue_foreach(queue, (GFunc) free_func, NULL);
    g_queue_free(queue);
}
#endif /* 2.32.0 */

#endif /* _STEAM_GLIB_H_ */
