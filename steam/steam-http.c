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

#include <bitlbee.h>
#include <string.h>

#include "steam-glib.h"
#include "steam-http.h"

static void steam_http_req_sendasm(SteamHttpReq *req);
static void steam_http_req_queue(SteamHttp *http, gboolean force);

static void steam_http_tree_ins(GTree *tree, SteamHttpPair *pair, va_list ap)
{
    SteamHttpPair *p;
    gchar         *key;
    gchar         *val;

    for (p = pair; p != NULL; ) {
        if (p->key == NULL)
            continue;

        key = g_strdup(p->key);
        val = g_strdup(p->val);

        g_tree_replace(tree, key, val);
        p = va_arg(ap, SteamHttpPair*);
    }
}

GQuark steam_http_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-http-error-quark");

    return q;
}

SteamHttp *steam_http_new(const gchar *agent)
{
    SteamHttp *http;

    http = g_new0(SteamHttp, 1);

    http->agent   = g_strdup(agent);
    http->queue   = g_queue_new();
    http->cookies = g_tree_new_full((GCompareDataFunc) g_ascii_strcasecmp,
                                    NULL, g_free, g_free);
    return http;
}

void steam_http_free_reqs(SteamHttp *http)
{
    SteamHttpReq *req;

    g_return_if_fail(http != NULL);

    http->flags &= ~STEAM_HTTP_FLAG_QUEUED;

    while ((req = g_queue_pop_tail(http->queue)) != NULL)
        steam_http_req_free(req);
}

void steam_http_free(SteamHttp *http)
{
    g_return_if_fail(http != NULL);

    steam_http_free_reqs(http);
    g_queue_free(http->queue);
    g_tree_destroy(http->cookies);

    g_free(http->agent);
    g_free(http);
}

void steam_http_queue_pause(SteamHttp *http, gboolean pause)
{
    SteamHttpReq *req;
    GList        *l;

    g_return_if_fail(http != NULL);

    if (pause) {
        for (l = http->queue->tail; l != NULL; l = l->prev)
            steam_http_req_close(l->data);

        http->flags |= STEAM_HTTP_FLAG_PAUSED;
        return;
    }

    http->flags &= ~STEAM_HTTP_FLAG_PAUSED;

    for (l = http->queue->tail; l != NULL; l = l->prev) {
        req = l->data;

        if (!(req->flags & STEAM_HTTP_REQ_FLAG_QUEUED) &&
            (req->request == NULL))
        {
            steam_http_req_sendasm(req);
        }
    }

    steam_http_req_queue(http, TRUE);
}

void steam_http_cookies_set(SteamHttp *http, SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(http != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(http->cookies, pair, ap);
    va_end(ap);
}

void steam_http_cookies_parse_req(SteamHttp *http, SteamHttpReq *req)
{
    gchar **hdrs;
    gchar **kv;
    gchar  *str;
    gsize   i;
    gsize   j;

    g_return_if_fail(http != NULL);
    g_return_if_fail(req  != NULL);

    if (req->request == NULL)
        return;

    hdrs = g_strsplit(req->request->reply_headers, "\r\n", 0);

    for (i = 0; hdrs[i] != NULL; i++) {
        if (g_ascii_strncasecmp(hdrs[i], "Set-Cookie", 10) != 0)
            continue;

        str = strchr(hdrs[i], ';');

        if (str != NULL);
            str[0] = 0;

        str = strchr(hdrs[i], ':');

        if (str == NULL)
            continue;

        str = g_strstrip(++str);
        kv  = g_strsplit(str, "=", 2);

        for (j = 0; kv[j] != NULL; j++) {
            str = steam_http_uri_unescape(kv[j]);
            g_free(kv[j]);
            kv[j] = str;
        }

        if (g_strv_length(kv) > 1)
            steam_http_cookies_set(http, STEAM_HTTP_PAIR(kv[0], kv[1]), NULL);

        g_strfreev(kv);
    }

    g_strfreev(hdrs);
}

void steam_http_cookies_parse_str(SteamHttp *http, const gchar *data)
{
    gchar **ckis;
    gchar **kv;
    gchar  *str;
    gsize   i;
    gsize   j;

    g_return_if_fail(http != NULL);
    g_return_if_fail(data != NULL);

    ckis = g_strsplit(data, ";", 0);

    for (i = 0; ckis[i] != NULL; i++) {
        str = g_strstrip(ckis[i]);
        kv  = g_strsplit(str, "=", 2);

        for (j = 0; kv[j] != NULL; j++) {
            str = steam_http_uri_unescape(kv[j]);
            g_free(kv[j]);
            kv[j] = str;
        }

        if (g_strv_length(kv) > 1)
            steam_http_cookies_set(http, STEAM_HTTP_PAIR(kv[0], kv[1]), NULL);

        g_strfreev(kv);
    }

    g_strfreev(ckis);
}

static gboolean steam_http_tree_cookies(gchar *key, gchar *val, GString *gstr)
{
    gchar *sep;

    if (val == NULL)
        val = "";

    key = steam_http_uri_escape(key);
    val = steam_http_uri_escape(val);

    sep = (gstr->len > 0) ? "; " : "";
    g_string_append_printf(gstr, "%s%s=%s", sep, key, val);

    g_free(key);
    g_free(val);
    return FALSE;
}

gchar *steam_http_cookies_str(SteamHttp *http)
{
    GString *gstr;

    g_return_val_if_fail(http != NULL, NULL);

    gstr = g_string_sized_new(128);
    g_tree_foreach(http->cookies, (GTraverseFunc) steam_http_tree_cookies,
                   gstr);
    return g_string_free(gstr, FALSE);
}

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data)
{
    SteamHttpReq *req;

    req = g_new0(SteamHttpReq, 1);

    req->http = http;
    req->host = g_strdup(host);
    req->port = port;
    req->path = g_strdup(path);
    req->func = func;
    req->data = data;

    req->headers = g_tree_new_full((GCompareDataFunc) g_ascii_strcasecmp,
                                   NULL, g_free, g_free);
    req->params  = g_tree_new_full((GCompareDataFunc) g_ascii_strcasecmp,
                                   NULL, g_free, g_free);

    steam_http_req_headers_set(req,
        STEAM_HTTP_PAIR("User-Agent", http->agent),
        STEAM_HTTP_PAIR("Host",       host),
        STEAM_HTTP_PAIR("Accept",     "*/*"),
        STEAM_HTTP_PAIR("Connection", "Close"),
        NULL
    );

    return req;
}

static void steam_http_req_close_nuller(struct http_request *request)
{

}

void steam_http_req_close(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    b_event_remove(req->toid);

    req->header    = NULL;
    req->body      = NULL;
    req->body_size = 0;
    req->toid      = 0;

    if (req->request != NULL) {
        /* Prevent more than one call to request->func() */
        req->request->func = steam_http_req_close_nuller;
        req->request->data = NULL;

        if (!(req->request->flags & STEAM_HTTP_CLIENT_FREED))
            http_close(req->request);

        req->request = NULL;
    }
}

void steam_http_req_free(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    steam_http_req_close(req);

    if (req->err != NULL)
        g_error_free(req->err);

    g_tree_destroy(req->headers);
    g_tree_destroy(req->params);

    g_free(req->path);
    g_free(req->host);
    g_free(req);
}

void steam_http_req_headers_set(SteamHttpReq *req, SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(req->headers, pair, ap);
    va_end(ap);
}

void steam_http_req_params_set(SteamHttpReq *req, SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(req->params, pair, ap);
    va_end(ap);
}

void steam_http_req_resend(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->err != NULL) {
        g_error_free(req->err);
        req->err = NULL;
    }

    req->flags |= STEAM_HTTP_REQ_FLAG_NOFREE | STEAM_HTTP_REQ_FLAG_RESEND;

    steam_http_req_close(req);
    steam_http_req_send(req);
}

static gboolean steam_http_req_done_error(gpointer data, gint fd,
                                          b_input_condition cond)
{
    SteamHttpReq *req = data;

    steam_http_req_sendasm(req);
    return FALSE;
}

static void steam_http_req_done(SteamHttpReq *req)
{
#ifdef DEBUG_STEAM
    const gchar  *str;
    gchar       **ls;
    guint         i;

    static gint8 debug = -1;

    if (G_UNLIKELY(debug < 0))
        debug = g_getenv("BITLBEE_DEBUG") || g_getenv("BITLBEE_DEBUG_STEAM");

    if (debug) {
        if (req->err != NULL)
            str = req->err->message;
        else if (req->request != NULL)
            str = req->request->status_string;
        else
            str = "Unknown status";

        g_print("HTTP Response (%p): %s:%d%s (%s)\n",
                req, req->host, req->port, req->path, str);

        if (req->rsc > 0)
            g_print("Reattempted request: #%u\n", req->rsc);

        if (req->header != NULL) {
            ls = g_strsplit(req->header, "\n", 0);

            for (i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_strfreev(ls);
        } else {
            g_print("  ** No header data returned **\n\n");
        }

        if (req->body_size > 0) {
            ls = g_strsplit(req->body, "\n", 0);

            for (i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_strfreev(ls);
        } else {
            g_print("  ** No body data returned **\n");
        }

        g_print("\n\n");
    }
#endif /* DEBUG_STEAM */

    if (req->err != NULL) {
        if (req->rsc < STEAM_HTTP_RESEND_MAX) {
            steam_http_req_close(req);
            g_error_free(req->err);
            req->err = NULL;

            req->toid = b_timeout_add(STEAM_HTTP_RESEND_TIMEOUT,
                                      steam_http_req_done_error, req);
            req->rsc++;
            return;
        }

        g_prefix_error(&req->err, "HTTP: ");
    }

    req->flags &= ~STEAM_HTTP_REQ_FLAG_NOFREE;
    g_queue_remove(req->http->queue, req);

    if (req->func != NULL)
        req->func(req, req->data);

    if (req->flags & STEAM_HTTP_REQ_FLAG_QUEUED)
        steam_http_req_queue(req->http, TRUE);

    if (!(req->flags & STEAM_HTTP_REQ_FLAG_NOFREE)) {
        steam_http_req_free(req);
        return;
    }

    req->flags &= ~STEAM_HTTP_REQ_FLAG_NOFREE;
    steam_http_req_close(req);
}

static void steam_http_req_cb(struct http_request *request)
{
    SteamHttpReq *req = request->data;

    req->header    = request->reply_headers;
    req->body      = request->reply_body;
    req->body_size = request->body_size;

    switch (request->status_code) {
    case 200:
    case 301:
    case 302:
    case 303:
    case 307:
        break;

    default:
        g_set_error(&req->err, STEAM_HTTP_ERROR, request->status_code,
                    "%s", request->status_string);
    }

    req->request->flags |= STEAM_HTTP_CLIENT_FREED;
    steam_http_req_done(req);
}

static gboolean steam_http_tree_headers(gchar *key, gchar *val, GString *gstr)
{
    if (val == NULL)
        val = "";

    g_string_append_printf(gstr, "%s: %s\r\n", key, val);
    return FALSE;
}

static gboolean steam_http_tree_params(gchar *key, gchar *val, GString *gstr)
{
    gchar *sep;

    if (val == NULL)
        val = "";

    key = steam_http_uri_escape(key);
    val = steam_http_uri_escape(val);

    sep = (gstr->len > 0) ? "&" : "";
    g_string_append_printf(gstr, "%s%s=%s", sep, key, val);

    g_free(key);
    g_free(val);
    return FALSE;
}

static gboolean steam_http_req_send_timeout(gpointer data, gint fd,
                                            b_input_condition cond)
{
    SteamHttpReq *req = data;

    req->toid = 0;
    g_set_error(&req->err, STEAM_HTTP_ERROR, 0, "Request timed out");

    steam_http_req_close(req);
    steam_http_req_done(req);
    return FALSE;
}

static void steam_http_req_sendasm(SteamHttpReq *req)
{
    GString *gstr;
    gchar   *hs;
    gchar   *ps;
    gchar   *len;
    gchar   *str;

    gstr = g_string_sized_new(128);
    g_tree_foreach(req->params, (GTraverseFunc) steam_http_tree_params, gstr);
    len = g_strdup_printf("%" G_GSIZE_FORMAT, gstr->len);
    ps  = g_string_free(gstr, FALSE);

    if (g_tree_nnodes(req->http->cookies) > 0) {
        str = steam_http_cookies_str(req->http);
        steam_http_req_headers_set(req, STEAM_HTTP_PAIR("Cookie", str), NULL);
        g_free(str);
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        steam_http_req_headers_set(req,
            STEAM_HTTP_PAIR("Content-Type",   "application/"
                                              "x-www-form-urlencoded"),
            STEAM_HTTP_PAIR("Content-Length", len),
            NULL
        );
    }

    gstr = g_string_sized_new(128);
    g_tree_foreach(req->headers, (GTraverseFunc) steam_http_tree_headers, gstr);
    hs = g_string_free(gstr, FALSE);

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        str = g_strdup_printf("POST %s HTTP/1.1\r\n%s\r\n%s",
                              req->path, hs, ps);
    } else {
        str = g_strdup_printf("GET %s?%s HTTP/1.1\r\n%s\r\n",
                              req->path, ps, hs);
    }

#ifdef DEBUG_STEAM
    gchar **ls;
    guint   i;

    static gint8 debug = -1;

    if (G_UNLIKELY(debug < 0))
        debug = g_getenv("BITLBEE_DEBUG") || g_getenv("BITLBEE_DEBUG_STEAM");

    if (debug) {
        g_print("HTTP Request (%p): %s:%d%s\n",
                req, req->host, req->port, req->path);

        if (req->rsc > 0)
            g_print("Reattempted request: #%u\n", req->rsc);

        if (hs != NULL) {
            ls = g_strsplit(hs, "\n", 0);

            for (i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_strfreev(ls);
        } else {
            g_print("  ** No header data **\n\n");
        }

        if (ps != NULL) {
            ls = g_strsplit(ps, "\n", 0);

            for (i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_strfreev(ls);
        } else {
            g_print("  ** No body data **\n");
        }

        g_print("\n\n");
    }
#endif /* DEBUG_STEAM */

    req->request = http_dorequest(req->host, req->port,
                                  (req->flags & STEAM_HTTP_REQ_FLAG_SSL),
                                  str, steam_http_req_cb, req);

    g_free(len);
    g_free(ps);
    g_free(hs);
    g_free(str);

    if (G_UNLIKELY(req->request == NULL)) {
        g_set_error(&req->err, STEAM_HTTP_ERROR, 0, "Failed to init request");
        steam_http_req_done(req);
        return;
    }

    /* Prevent automatic redirection */
    req->request->redir_ttl = 0;

    if (req->timeout > 0) {
        req->toid = b_timeout_add(req->timeout, steam_http_req_send_timeout,
                                  req);
    }
}

static void steam_http_req_queue(SteamHttp *http, gboolean force)
{
    SteamHttpReq *req;
    SteamHttpReq *treq;
    GList        *l;

    if ((http->flags & STEAM_HTTP_FLAG_PAUSED) ||
        (!force && (http->flags & STEAM_HTTP_FLAG_QUEUED)))
    {
        return;
    }

    req = NULL;

    for (l = http->queue->tail; l != NULL; l = l->prev) {
        treq = l->data;

        if (treq->flags & STEAM_HTTP_REQ_FLAG_QUEUED) {
            req = l->data;
            break;
        }
    }

    if (req == NULL) {
        http->flags &= ~STEAM_HTTP_FLAG_QUEUED;
        return;
    } else {
        http->flags |= STEAM_HTTP_FLAG_QUEUED;
    }

    steam_http_req_sendasm(req);

    if (G_UNLIKELY(req->request == NULL))
        g_queue_remove(req->http->queue, req);
}

void steam_http_req_send(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->flags & STEAM_HTTP_REQ_FLAG_NOWAIT) {
        g_queue_push_tail(req->http->queue, req);
        steam_http_req_sendasm(req);
        return;
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_RESEND)
        g_queue_push_tail(req->http->queue, req);
    else
        g_queue_push_head(req->http->queue, req);

    if (req->flags & STEAM_HTTP_REQ_FLAG_QUEUED) {
        steam_http_req_queue(req->http, FALSE);
        return;
    }

    if (!(req->http->flags & STEAM_HTTP_FLAG_PAUSED))
        steam_http_req_sendasm(req);
}

gchar *steam_http_uri_escape(const gchar *unescaped)
{
    gchar *ret;
    gchar *str;

    g_return_val_if_fail(unescaped != NULL, NULL);

    str = g_strndup(unescaped, (strlen(unescaped) * 3) + 1);
    http_encode(str);

    ret = g_strdup(str);
    g_free(str);

    return ret;
}

gchar *steam_http_uri_unescape(const gchar *escaped)
{
    gchar *ret;
    gchar *str;

    g_return_val_if_fail(escaped != NULL, NULL);

    str = g_strdup(escaped);
    http_decode(str);

    ret = g_strdup(str);
    g_free(str);

    return ret;
}
