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

#ifndef _STEAM_HTTP_H
#define _STEAM_HTTP_H

#include <glib.h>
#include <http_client.h>

#define STEAM_HTTP_ERROR_MAX      3
#define STEAM_HTTP_ERROR_TIMEOUT  2000

typedef enum   _SteamHttpReqFlags SteamHttpReqFlags;
typedef enum   _SteamHttpFlags    SteamHttpFlags;
typedef struct _SteamHttp         SteamHttp;
typedef struct _SteamHttpReq      SteamHttpReq;

typedef void (*SteamHttpFunc) (SteamHttpReq *req, gpointer data);

enum _SteamHttpFlags
{
    STEAM_HTTP_FLAG_PAUSED = 1 << 0,
    STEAM_HTTP_FLAG_QUEUED = 1 << 1
};

enum _SteamHttpReqFlags
{
    STEAM_HTTP_REQ_FLAG_GET    = 1 << 0,
    STEAM_HTTP_REQ_FLAG_POST   = 1 << 1,
    STEAM_HTTP_REQ_FLAG_SSL    = 1 << 2,

    STEAM_HTTP_REQ_FLAG_NOFREE = 1 << 3,
    STEAM_HTTP_REQ_FLAG_QUEUED = 1 << 4
};

struct _SteamHttp
{
    SteamHttpFlags flags;

    gchar  *agent;
    GQueue *reqq;
};

struct _SteamHttpReq
{
    SteamHttp         *http;
    SteamHttpReqFlags  flags;

    gchar *host;
    gint   port;
    gchar *path;

    GHashTable *headers;
    GHashTable *params;

    SteamHttpFunc func;
    gpointer      data;

    struct http_request *request;

    GError *err;
    gchar  *body;
    gint    body_size;

    guint8 errc;
    gint   rsid;
};

#define STEAM_HTTP_ERROR steam_http_error_quark()

GQuark steam_http_error_quark(void);

SteamHttp *steam_http_new(const gchar *agent);

void steam_http_free_reqs(SteamHttp *http);

void steam_http_free(SteamHttp *http);

void steam_http_queue_pause(SteamHttp *http, gboolean puase);

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data);

void steam_http_req_free(SteamHttpReq *req);

void steam_http_req_headers_set(SteamHttpReq *req, gsize size, ...);

void steam_http_req_params_set(SteamHttpReq *req, gsize size, ...);

void steam_http_req_resend(SteamHttpReq *req);

void steam_http_req_send(SteamHttpReq *req);

gchar *steam_http_uri_escape(const gchar *unescaped);

#endif /* _STEAM_HTTP_H */
