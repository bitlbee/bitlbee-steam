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

#define STEAM_HTTP_CLIENT_FREED   (1 << 31)
#define STEAM_HTTP_RESEND_MAX     3
#define STEAM_HTTP_RESEND_TIMEOUT 2000

#define STEAM_HTTP_PAIR(k, v) ((SteamHttpPair *) &((SteamHttpPair) {k, v}))

typedef enum   _SteamHttpFlags    SteamHttpFlags;
typedef enum   _SteamHttpReqFlags SteamHttpReqFlags;
typedef struct _SteamHttp         SteamHttp;
typedef struct _SteamHttpPair     SteamHttpPair;
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
    STEAM_HTTP_REQ_FLAG_NOWAIT = 1 << 4,
    STEAM_HTTP_REQ_FLAG_QUEUED = 1 << 5,
    STEAM_HTTP_REQ_FLAG_RESEND = 1 << 6
};

struct _SteamHttp
{
    SteamHttpFlags flags;

    gchar  *agent;
    GTree  *cookies;
    GQueue *queue;
};

struct _SteamHttpPair
{
    const gchar *key;
    const gchar *val;
};

struct _SteamHttpReq
{
    SteamHttp         *http;
    SteamHttpReqFlags  flags;

    gchar *host;
    gint   port;
    gchar *path;
    gint   timeout;

    GTree *headers;
    GTree *params;

    SteamHttpFunc func;
    gpointer      data;

    struct http_request *request;

    GError *err;
    gchar  *header;
    gchar  *body;
    gint    body_size;

    gint   toid;
    guint8 rsc;
};

#define STEAM_HTTP_ERROR steam_http_error_quark()

GQuark steam_http_error_quark(void);

SteamHttp *steam_http_new(const gchar *agent);

void steam_http_free_reqs(SteamHttp *http);

void steam_http_free(SteamHttp *http);

void steam_http_queue_pause(SteamHttp *http, gboolean puase);

void steam_http_cookies_set(SteamHttp *http, SteamHttpPair *pair, ...)
    G_GNUC_NULL_TERMINATED;

void steam_http_cookies_parse_req(SteamHttp *http, SteamHttpReq *req);

void steam_http_cookies_parse_str(SteamHttp *http, const gchar *data);

gchar *steam_http_cookies_str(SteamHttp *http);

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data);

void steam_http_req_close(SteamHttpReq *req);

void steam_http_req_free(SteamHttpReq *req);

void steam_http_req_headers_set(SteamHttpReq *req, SteamHttpPair *pair, ...)
    G_GNUC_NULL_TERMINATED;

void steam_http_req_params_set(SteamHttpReq *req, SteamHttpPair *pair, ...)
    G_GNUC_NULL_TERMINATED;

void steam_http_req_resend(SteamHttpReq *req);

void steam_http_req_send(SteamHttpReq *req);

gchar *steam_http_uri_escape(const gchar *unescaped);

gchar *steam_http_uri_unescape(const gchar *escaped);

#endif /* _STEAM_HTTP_H */
