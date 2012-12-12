/*
 * Copyright 2012 James Geboski <jgeboski@gmail.com>
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

typedef enum   _SteamHttpFlags SteamHttpFlags;
typedef struct _SteamHttp      SteamHttp;
typedef struct _SteamHttpReq   SteamHttpReq;

typedef gboolean (*SteamHttpFunc) (SteamHttpReq *req, gpointer data);

enum _SteamHttpFlags
{
    STEAM_HTTP_FLAG_GET = 0,
    STEAM_HTTP_FLAG_POST,
    STEAM_HTTP_FLAG_SSL
};

struct _SteamHttp
{
    gchar  *agent;
    GSList *requests;
};

struct _SteamHttpReq
{
    SteamHttp      *http;
    SteamHttpFlags  flags;

    gchar *host;
    gint   port;
    gchar *path;

    GTree *headers;
    GTree *params;

    SteamHttpFunc func;
    gpointer      data;

    struct http_request *request;

    gint   errcode;
    gchar *errstr;

    gchar *body;
    gint   body_size;
};


SteamHttp *steam_http_new(const gchar *agent);

void steam_http_free_reqs(SteamHttp *http);

void steam_http_free(SteamHttp *http);

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data);

void steam_http_req_free(SteamHttpReq *req);

void steam_http_req_headers_set(SteamHttpReq *req, gsize size, ...);

void steam_http_req_params_set(SteamHttpReq *req, gsize size, ...);

void steam_http_req_send(SteamHttpReq *req);

#endif /* _STEAM_HTTP_H */
