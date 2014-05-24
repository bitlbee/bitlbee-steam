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

/** @file **/

#ifndef _STEAM_HTTP_H
#define _STEAM_HTTP_H

#include <glib.h>
#include <http_client.h>


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


/** The flags of #SteamHttp. **/
typedef enum _SteamHttpFlags SteamHttpFlags;

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
 * The flags of #SteamHttp.
 **/
enum _SteamHttpFlags
{
    STEAM_HTTP_FLAG_PAUSED = 1 << 0, /** The queue is paused **/
    STEAM_HTTP_FLAG_QUEUED = 1 << 1  /** The queue is queued **/
};

/**
 * The flags of #SteamHttpReq.
 **/
enum _SteamHttpReqFlags
{
    STEAM_HTTP_REQ_FLAG_GET    = 1 << 0, /** Use the GET method **/
    STEAM_HTTP_REQ_FLAG_POST   = 1 << 1, /** Use the POST method **/
    STEAM_HTTP_REQ_FLAG_SSL    = 1 << 2, /** Use encryption via SSL **/

    STEAM_HTTP_REQ_FLAG_NOFREE = 1 << 3, /** Skip freeing the #SteamHttpReq **/
    STEAM_HTTP_REQ_FLAG_NOWAIT = 1 << 4, /** Skip the queue blockade **/
    STEAM_HTTP_REQ_FLAG_QUEUED = 1 << 5, /** Wait on the queue **/
    STEAM_HTTP_REQ_FLAG_RESEND = 1 << 6  /** Resend the #SteamHttpReq **/
};

/**
 * The structure for managing #SteamHttpReq.
 **/
struct _SteamHttp
{
    SteamHttpFlags flags; /** The #SteamHttpFlags. **/

    gchar  *agent;        /** The agent. **/
    GTree  *cookies;      /** The #GTree of cookies. **/
    GQueue *queue;        /** The #GQueue of #SteamHttpReq. **/
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

    GTree *headers;               /** The #GTree of headers. **/
    GTree *params;                /** The #GTree of parameters. **/

    SteamHttpFunc func;           /** The user callback function or NULL. **/
    gpointer      data;           /** The user define data or NULL. **/

    struct http_request *request; /** The underlying #http_request. **/

    GError *err;                  /** The #GError or NULL. **/
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

void steam_http_queue_pause(SteamHttp *http, gboolean puase);

void steam_http_cookies_set(SteamHttp *http, const SteamHttpPair *pair, ...)
    G_GNUC_NULL_TERMINATED;

void steam_http_cookies_parse_req(SteamHttp *http, const SteamHttpReq *req);

void steam_http_cookies_parse_str(SteamHttp *http, const gchar *data);

gchar *steam_http_cookies_str(SteamHttp *http);

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data);

void steam_http_req_close(SteamHttpReq *req);

void steam_http_req_free(SteamHttpReq *req);

void steam_http_req_headers_set(SteamHttpReq *req, const SteamHttpPair *pair,
                                ...) G_GNUC_NULL_TERMINATED;

void steam_http_req_params_set(SteamHttpReq *req, const SteamHttpPair *pair,
                               ...) G_GNUC_NULL_TERMINATED;

void steam_http_req_resend(SteamHttpReq *req);

void steam_http_req_send(SteamHttpReq *req);

gchar *steam_http_uri_escape(const gchar *unescaped);

gchar *steam_http_uri_unescape(const gchar *escaped);

#endif /* _STEAM_HTTP_H */
