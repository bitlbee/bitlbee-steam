/*
 * Copyright 2012-2015 James Geboski <jgeboski@gmail.com>
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

/** @file **/

#ifndef _STEAM_HTTP_H
#define _STEAM_HTTP_H

#include <http_client.h>

#include "steam-glib.h"

#define STEAM_HTTP_CLIENT_FREED   (1 << 31)
#define STEAM_HTTP_RESEND_MAX     3
#define STEAM_HTTP_RESEND_TIMEOUT 2000


/**
 * Creates a #SteamHttpPair in-line.
 *
 * @param k The key.
 * @param v The value.
 *
 * @return The resulting SteamHttpPair.
 **/
#define STEAM_HTTP_PAIR(k, v) ((SteamHttpPair *) &((SteamHttpPair) {k, v}))


/** The #GError codes of #SteamHttp. **/
typedef enum _SteamHttpError SteamHttpError;

/** The flags of #SteamHttpReq. **/
typedef enum _SteamHttpReqFlags SteamHttpReqFlags;

/** The structure for managing #SteamHttpReq. **/
typedef struct _SteamHttp SteamHttp;

/** The structure for key/value pairs of strings. **/
typedef struct _SteamHttpPair SteamHttpPair;

/** The structure for a #SteamHttp request. **/
typedef struct _SteamHttpReq SteamHttpReq;


/**
 * The type of callback for #SteamHttpReq operations.
 *
 * @param req  The #SteamHttpReq.
 * @param data The user defined data or NULL.
 **/
typedef void (*SteamHttpFunc) (SteamHttpReq *req, gpointer data);


/**
 * The #GError codes of #SteamHttp.
 **/
enum _SteamHttpError
{
    STEAM_HTTP_ERROR_CLOSED = 1, /** Closed **/
    STEAM_HTTP_ERROR_INIT,       /** Initializing **/
    STEAM_HTTP_ERROR_TIMEOUT,    /** Timeout **/
};

/**
 * The flags of #SteamHttpReq.
 **/
enum _SteamHttpReqFlags
{
    STEAM_HTTP_REQ_FLAG_GET    = 1 << 0, /** Use the GET method **/
    STEAM_HTTP_REQ_FLAG_POST   = 1 << 1, /** Use the POST method **/
    STEAM_HTTP_REQ_FLAG_SSL    = 1 << 2  /** Use encryption via SSL **/
};

/**
 * The structure for managing #SteamHttpReq.
 **/
struct _SteamHttp
{
    gchar      *agent;   /** The agent. **/
    GHashTable *cookies; /** The #GHashTable of cookies. **/
    GHashTable *reqs;    /** The #GHashTable of #SteamHttpReq. **/
};

/**
 * The structure for key/value pairs of strings.
 **/
struct _SteamHttpPair
{
    const gchar *key; /** The Key. **/
    const gchar *val; /** The value. **/
};

/**
 * he structure for a #SteamHttp request.
 **/
struct _SteamHttpReq
{
    SteamHttp         *http;      /** The #SteamHttp. **/
    SteamHttpReqFlags  flags;     /** The #SteamHttpReqFlags. **/

    gchar *host;                  /** The hostname. **/
    gint   port;                  /** The port number. **/
    gchar *path;                  /** The pathname. **/
    gint   timeout;               /** The timeout. **/

    GHashTable *headers;          /** The #GHashTable of headers. **/
    GHashTable *params;           /** The #GHashTable of parameters. **/

    SteamHttpFunc func;           /** The user callback function or NULL. **/
    gpointer      data;           /** The user define data or NULL. **/

    struct http_request *request; /** The underlying #http_request. **/

    GError *err;                  /** The #GError or NULL. **/
    gchar  *status;               /** Shortcut to request->status_string. **/
    gint    scode;                /** Shortcut to request->status_code. **/
    gchar  *header;               /** Shortcut to request->reply_headers. **/
    gchar  *body;                 /** Shortcut to request->reply_body. **/
    gint    body_size;            /** Shortcut to request->body_size. **/

    gint   toid;                  /** The event ID for the timeout. **/
    guint8 rsc;                   /** The resend count. **/
};


#define STEAM_HTTP_ERROR steam_http_error_quark()

GQuark steam_http_error_quark(void);

SteamHttp *steam_http_new(const gchar *agent);

void steam_http_free_reqs(SteamHttp *http);

void steam_http_free(SteamHttp *http);

void steam_http_cookies_set(SteamHttp *http, const SteamHttpPair *pair, ...)
    G_GNUC_NULL_TERMINATED;

void steam_http_cookies_parse_req(SteamHttp *http, const SteamHttpReq *req);

void steam_http_cookies_parse_str(SteamHttp *http, const gchar *data);

gchar *steam_http_cookies_str(SteamHttp *http);

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data);

void steam_http_req_free(SteamHttpReq *req);

void steam_http_req_headers_set(SteamHttpReq *req, const SteamHttpPair *pair,
                                ...) G_GNUC_NULL_TERMINATED;

void steam_http_req_params_set(SteamHttpReq *req, const SteamHttpPair *pair,
                               ...) G_GNUC_NULL_TERMINATED;

void steam_http_req_send(SteamHttpReq *req);

gchar *steam_http_uri_escape(const gchar *unescaped);

gchar *steam_http_uri_unescape(const gchar *escaped);

#endif /* _STEAM_HTTP_H */
