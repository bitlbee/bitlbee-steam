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

#ifndef _STEAM_HTTP_H_
#define _STEAM_HTTP_H_

/**
 * SECTION:http
 * @section_id: steam-http
 * @short_description: <filename>steam-http.h</filename>
 * @title: HTTP Client
 *
 * The HTTP client.
 */

#include <http_client.h>

#include "steam-glib.h"

/**
 * STEAM_HTTP_CLIENT_FREED:
 *
 * Flag denoting the HTTP request as being freed elsewhere.
 */
#define STEAM_HTTP_CLIENT_FREED  (1 << 31)

/**
 * STEAM_HTTP_RESEND_MAX:
 *
 * The maximum amount of times to resend a failed request.
 */
#define STEAM_HTTP_RESEND_MAX  3

/**
 * STEAM_HTTP_RESEND_TIMEOUT:
 *
 * The timeout (in milliseconds) between resend attempts.
 */
#define STEAM_HTTP_RESEND_TIMEOUT  2000

/**
 * STEAM_HTTP_ERROR:
 *
 * The #GQuark of the domain of HTTP errors.
 */
#define STEAM_HTTP_ERROR  steam_http_error_quark()

/**
 * STEAM_HTTP_PAIR:
 * @k: The key.
 * @v: The value.
 *
 * Creates a #SteamHttpPair in-line.
 *
 * Returns: The resulting SteamHttpPair.
 */
#define STEAM_HTTP_PAIR(k, v)  ((SteamHttpPair *) &((SteamHttpPair) {k, v}))

typedef struct _SteamHttp SteamHttp;
typedef struct _SteamHttpPair SteamHttpPair;
typedef struct _SteamHttpReq SteamHttpReq;

/**
 * SteamHttpFunc:
 * @req: The #SteamHttpReq.
 * @data: The user defined data or #NULL.
 *
 * The type of callback for #SteamHttpReq operations.
 */
typedef void (*SteamHttpFunc) (SteamHttpReq *req, gpointer data);

/**
 * SteamHttpError:
 * @STEAM_HTTP_ERROR_CLOSED: Request closed.
 * @STEAM_HTTP_ERROR_INIT: Initialization failed.
 * @STEAM_HTTP_ERROR_TIMEOUT: Request timed out.
 *
 * The error codes for the #STEAM_HTTP_ERROR domain.
 */
typedef enum
{
    STEAM_HTTP_ERROR_CLOSED = 1,
    STEAM_HTTP_ERROR_INIT,
    STEAM_HTTP_ERROR_TIMEOUT
} SteamHttpError;

/**
 * SteamHttpReqFlags:
 * @STEAM_HTTP_REQ_FLAG_GET: Use the GET method.
 * @STEAM_HTTP_REQ_FLAG_POST: Use the POST method.
 * @STEAM_HTTP_REQ_FLAG_SSL: Use encryption via HTTPS.
 *
 * The #SteamHttpReq flags.
 */
typedef enum
{
    STEAM_HTTP_REQ_FLAG_GET = 1 << 0,
    STEAM_HTTP_REQ_FLAG_POST = 1 << 1,
    STEAM_HTTP_REQ_FLAG_SSL = 1 << 2
} SteamHttpReqFlags;

/**
 * SteamHttp:
 * @agent: The user-agent string.
 * @cookies: The table of cookies.
 * @reqs: The table of #SteamHttpReq.
 *
 * Represents an HTTP client (a set of #SteamHttpReq).
 */
struct _SteamHttp
{
    gchar *agent;
    GHashTable *cookies;
    GHashTable *reqs;
};

/**
 * SteamHttpPair:
 * @key: The key.
 * @val: The value.
 *
 * Represents a key/value pair of strings.
 */
struct _SteamHttpPair
{
    const gchar *key;
    const gchar *val;
};

/**
 * SteamHttpReq:
 * @http: The #SteamHttp.
 * @flags: The #SteamHttpReqFlags.
 * @host: The hostname.
 * @port: The port number.
 * @path: The pathname.
 * @timeout: The timeout.
 * @headers: The table of headers.
 * @params: The table of parameters.
 * @func: The #SteamHttpFunc or #NULL.
 * @request: The underlying #http_request.
 * @err: The #GError or #NULL.
 * @status: Shortcut to `request->status_string`.
 * @scode: Shortcut to `request->status_code`.
 * @header: Shortcut to `request->reply_headers`.
 * @body: Shortcut to `request->reply_body`.
 * @body_size: Shortcut to `request->body_size`.
 * @toid: The event identifier for the timeout.
 * @rsc: The resend count.
 *
 * Represents a #SteamHttp request.
 */
struct _SteamHttpReq
{
    SteamHttp *http;
    SteamHttpReqFlags flags;

    gchar *host;
    gint port;
    gchar *path;
    gint timeout;

    GHashTable *headers;
    GHashTable *params;

    SteamHttpFunc func;
    gpointer data;
    struct http_request *request;

    GError *err;
    gchar *status;
    gint scode;
    gchar *header;
    gchar *body;
    gint body_size;

    gint toid;
    guint8 rsc;
};

/**
 * steam_http_error_quark:
 *
 * Gets the #GQuark of the domain of HTTP errors.
 *
 * Returns: The #GQuark of the domain.
 */
GQuark
steam_http_error_quark(void);

/**
 * steam_http_new:
 * @agent: The HTTP agent.
 *
 * Creates a new #SteamHttp. The returned #SteamHttp should be freed
 * with #steam_http_free() when no longer needed.
 *
 * Returns: The #SteamHttp.
 */
SteamHttp *
steam_http_new(const gchar *agent);

/**
 * steam_http_free_reqs:
 * @http: The #SteamHttp.
 *
 * Frees all #SteamHttpReq inside the #SteamHttp.
 */
void
steam_http_free_reqs(SteamHttp *http);

/**
 * steam_http_free:
 * @http: The #SteamHttp.
 *
 * Frees all memory used by the #SteamHttp.
 */
void
steam_http_free(SteamHttp *http);

/**
 * steam_http_cookies_get:
 * @http: The #SteamHttp.
 * @name: The cookie name.
 *
 * Gets the value of a cookie from the #SteamHttp.
 *
 * Returns: The value of the cookie, or #NULL for a nonexistent cookie.
 */
const gchar *
steam_http_cookies_get(SteamHttp *http, const gchar *name);

/**
 * steam_http_cookies_set:
 * @http: The #SteamHttp.
 * @pair: The first #SteamHttpPair.
 * @...: The additional #SteamHttpPair.
 *
 * Sets cookies from the #SteamHttpPair. If a cookie already exists, it
 * is overwritten with the new value.
 */
void
steam_http_cookies_set(SteamHttp *http, const SteamHttpPair *pair, ...)
                       G_GNUC_NULL_TERMINATED;

/**
 * steam_http_cookies_parse_req:
 * @http: The #SteamHttp.
 * @req: The #SteamHttpReq.
 *
 * Parses cookies from the #SteamHttpReq. If a cookie already exists,
 * it is overwritten with the new value.
 */
void
steam_http_cookies_parse_req(SteamHttp *http, const SteamHttpReq *req);

/**
 * steam_http_cookies_parse_str:
 * @http: The #SteamHttp.
 * @data: The string.
 *
 * Parses cookies from the string. If a cookie already exists, it is
 * overwritten with the new value.
 */
void
steam_http_cookies_parse_str(SteamHttp *http, const gchar *data);

/**
 * steam_http_cookies_str:
 * @http: The #SteamHttp.
 *
 * Gets a string representation of the cookies of the #SteamHttp. The
 * returned string should be freed with #g_free() when no longer
 * needed.
 *
 * Returns: The string representation.
 */
gchar *
steam_http_cookies_str(SteamHttp *http);

/**
 * steam_http_req_new:
 * @http: The #SteamHttp.
 * @host: The hostname.
 * @port: The port number.
 * @path: The pathname.
 * @func: The user callback function or #NULL.
 * @data: The user define data or #NULL.
 *
 * Creates a new #SteamHttpReq. The returned #SteamHttpReq should be
 * freed with #steam_http_req_free() when no longer needed.
 *
 * Returns: The #SteamHttpReq.
 */
SteamHttpReq *
steam_http_req_new(SteamHttp *http, const gchar *host, gint port,
                   const gchar *path, SteamHttpFunc func, gpointer data);

/**
 * steam_http_req_free:
 * @req: The #SteamHttpReq.
 *
 * Frees all memory used by the #SteamHttpReq.
 */
void
steam_http_req_free(SteamHttpReq *req);

/**
 * steam_http_req_headers_set:
 * @req: The #SteamHttpReq.
 * @pair: The first #SteamHttpPair.
 * @...: The additional #SteamHttpPair.
 *
 * Sets headers from the #SteamHttpPair. If a header already exists, it
 * is overwritten with the new value.
 */
void
steam_http_req_headers_set(SteamHttpReq *req, const SteamHttpPair *pair, ...)
                           G_GNUC_NULL_TERMINATED;

/**
 * steam_http_req_params_set:
 * @req: The #SteamHttpReq.
 * @pair: The first #SteamHttpPair.
 * @...: The additional #SteamHttpPair.
 *
 * Sets parameters from the #SteamHttpPair. If a parameter already
 * exists, it is overwritten with the new value.
 */
void
steam_http_req_params_set(SteamHttpReq *req, const SteamHttpPair *pair, ...)
                          G_GNUC_NULL_TERMINATED;

/**
 * steam_http_req_send:
 * @req: The #SteamHttpReq.
 *
 * Sends a #SteamHttpReq.
 */
void
steam_http_req_send(SteamHttpReq *req);

/**
 * steam_http_uri_escape:
 * @unescaped: The string.
 *
 * Escapes the characters of the string to make it URL safe. The
 * returned string should be freed with #g_free() when no longer
 * needed.
 *
 * Returns: The escaped string or #NULL on error.
 */
gchar *
steam_http_uri_escape(const gchar *unescaped);

/**
 * steam_http_uri_unescape:
 * @escaped: The string.
 *
 * Unescapes the characters of the string to make it a normal string.
 * The returned string should be freed with #g_free() when no longer
 * needed.
 *
 * Returns: The unescaped string or #NULL on error.
 */
gchar *
steam_http_uri_unescape(const gchar *escaped);

#endif /* _STEAM_HTTP_H_ */
