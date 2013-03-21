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

#include "steam-http.h"
#include "steam-util.h"

global_t global;

static void steam_http_req_queue(SteamHttp *http, gboolean force);

GQuark steam_http_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0))
        q = g_quark_from_static_string("steam-http-error-quark");

    return q;
}

SteamHttp *steam_http_new(const gchar *agent, GDestroyNotify ddfunc)
{
    SteamHttp *http;

    http = g_new0(SteamHttp, 1);

    http->ddfunc = ddfunc;
    http->agent  = g_strdup(agent);
    http->reqq   = g_queue_new();

    return http;
}

void steam_http_free_reqs(SteamHttp *http)
{
    SteamHttpReq *req;

    g_return_if_fail(http != NULL);

    http->flags &= ~STEAM_HTTP_FLAG_QUEUED;

    while ((req = g_queue_pop_tail(http->reqq)) != NULL)
        steam_http_req_free(req);
}

void steam_http_free(SteamHttp *http)
{
    g_return_if_fail(http != NULL);

    steam_http_free_reqs(http);
    g_queue_free(http->reqq);

    g_free(http->agent);
    g_free(http);
}

void steam_http_queue_pause(SteamHttp *http, gboolean pause)
{
    g_return_if_fail(http != NULL);

    if (!pause) {
        http->flags &= ~STEAM_HTTP_FLAG_PAUSED;
        steam_http_req_queue(http, TRUE);
    } else {
        http->flags |= STEAM_HTTP_FLAG_PAUSED;
    }
}

SteamHttpReq *steam_http_req_new(SteamHttp *http, const gchar *host,
                                 gint port, const gchar *path,
                                 SteamHttpFunc func, gpointer data)
{
    SteamHttpReq *req;

    req = g_new0(SteamHttpReq, 1);

    req->http   = http;
    req->host   = g_strdup(host);
    req->port   = port;
    req->path   = g_strdup(path);
    req->func   = func;
    req->data   = data;
    req->ddfunc = http->ddfunc;

    req->headers = g_hash_table_new_full(g_str_hash,
                                         (GEqualFunc) g_ascii_strcasecmp,
                                         g_free, g_free);
    req->params  = g_hash_table_new_full(g_str_hash,
                                         (GEqualFunc) g_ascii_strcasecmp,
                                         g_free, g_free);

    steam_http_req_headers_set(req, 4,
        "User-Agent", http->agent,
        "Host",       host,
        "Accept",     "*/*",
        "Connection", "Close"
    );

    return req;
}

static void steam_http_req_free_noreq(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->rsid > 0)
        b_event_remove(req->rsid);

    if ((req->ddfunc != NULL) && (req->data != NULL))
        req->ddfunc(req->data);

    if (req->err != NULL)
        g_error_free(req->err);

    g_hash_table_destroy(req->headers);
    g_hash_table_destroy(req->params);

    g_free(req->path);
    g_free(req->host);
    g_free(req);
}

void steam_http_req_free(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    http_close(req->request);
    steam_http_req_free_noreq(req);
}

static void steam_http_req_ins(GHashTable *table, gsize size, gboolean escape,
                               va_list ap)
{
    gchar *key;
    gchar *val;
    gsize  i;

    g_return_if_fail(table != NULL);

    if (G_UNLIKELY(size < 1))
        return;

    for (i = 0; i < size; i++) {
        key = va_arg(ap, gchar*);
        val = va_arg(ap, gchar*);

        if (key == NULL)
            continue;

        if (escape)
            key = steam_http_uri_escape(key);
        else
            key = g_strdup(key);

        if (escape && (val != NULL))
            val = steam_http_uri_escape(val);
        else
            val = g_strdup(val);

        g_hash_table_insert(table, key, val);
    }
}

void steam_http_req_headers_set(SteamHttpReq *req, gsize size, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, size);
    steam_http_req_ins(req->headers, size, FALSE, ap);
    va_end(ap);
}

void steam_http_req_params_set(SteamHttpReq *req, gsize size, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, size);
    steam_http_req_ins(req->params, size, TRUE, ap);
    va_end(ap);
}

void steam_http_req_resend(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->rsid > 0)
        b_event_remove(req->rsid);

    if (req->err != NULL) {
        g_error_free(req->err);
        req->err = NULL;
    }

    req->flags     |= STEAM_HTTP_REQ_FLAG_NOFREE;
    req->request    = NULL;
    req->body       = NULL;
    req->body_size  = 0;
    req->errc       = 0;

    steam_http_req_send(req);
}

static gboolean steam_http_req_resend_e(gpointer data, gint fd,
                                        b_input_condition cond)
{
    SteamHttpReq *req = data;

    g_return_val_if_fail(req != NULL, FALSE);

    req->rsid = 0;
    steam_http_req_send(req);
    return FALSE;
}

static void steam_http_req_cb(struct http_request *request)
{
    SteamHttpReq  *req = request->data;
    gchar        **ls;
    guint          i;

    g_queue_remove(req->http->reqq, req);

    /* Shortcut some req->request values into req */
    req->body      = request->reply_body;
    req->body_size = request->body_size;

    if (global.conf->verbose) {
        g_print("HTTP Reply (%s): %s\n", req->path, request->status_string);

        if (req->errc > 0)
            g_print("Reattempted request: #%u\n", req->errc);

        if (req->body_size > 0) {
            ls = g_strsplit(req->body, "\n", 0);

            for (i = 0; ls[i] != NULL; i++)
                g_print("  %s\n", ls[i]);

            g_strfreev(ls);
        } else {
            g_print("  ** No HTTP data returned **\n");
        }

        g_print("\n");
    }

    if (req->rsid > 0) {
        b_event_remove(req->rsid);
        req->rsid = 0;
    }

    if (request->status_code != 200) {
        g_set_error(&req->err, STEAM_HTTP_ERROR, request->status_code,
                    "%s", request->status_string);
    } else if (req->body_size < 1) {
        g_set_error(&req->err, STEAM_HTTP_ERROR, request->status_code,
                    "Empty reply");
    }

    if (req->err != NULL) {
        req->errc++;

        if (req->errc < STEAM_HTTP_ERROR_MAX) {
            g_error_free(req->err);
            req->err = NULL;

            req->rsid = b_timeout_add(STEAM_HTTP_ERROR_TIMEOUT,
                                      steam_http_req_resend_e, req);
            return;
        }

        g_prefix_error(&req->err, "HTTP: ");
    }

    if (req->func != NULL)
        req->func(req, req->data);

    if (req->flags & STEAM_HTTP_REQ_FLAG_QUEUED)
        steam_http_req_queue(req->http, TRUE);

    if (!(req->flags & STEAM_HTTP_REQ_FLAG_NOFREE))
        steam_http_req_free_noreq(req);
}

static gboolean steam_table_headers(gchar *key, gchar *val, GString *gstr)
{
    if (key == NULL)
        return FALSE;

    if (val == NULL)
        val = "";

    g_string_append_printf(gstr, "%s: %s\r\n", key, val);
    return FALSE;
}

static gboolean steam_table_params(gchar *key, gchar *val, GString *gstr)
{
    gchar *sep;

    if (key == NULL)
        return FALSE;

    if (val == NULL)
        val = "";

    sep = (gstr->len > 0) ? "&" : "";

    g_string_append_printf(gstr, "%s%s=%s", sep, key, val);
    return FALSE;
}

static gchar *steam_http_req_assemble(SteamHttpReq *req)
{
    GString  *gstr;
    gchar    *sreq;
    gchar    *hs;
    gchar    *ps;
    gchar    *len;

    g_return_val_if_fail(req != NULL, NULL);

    gstr = g_string_sized_new(128);
    g_hash_table_foreach(req->params, (GHFunc) steam_table_params, gstr);
    len = g_strdup_printf("%" G_GSIZE_FORMAT, gstr->len);
    ps  = g_string_free(gstr, FALSE);

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        steam_http_req_headers_set(req, 2,
            "Content-Type",   "application/x-www-form-urlencoded",
            "Content-Length", len
        );
    }

    gstr = g_string_sized_new(128);
    g_hash_table_foreach(req->headers, (GHFunc) steam_table_headers, gstr);
    hs = g_string_free(gstr, FALSE);

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        sreq = g_strdup_printf("POST %s HTTP/1.1\r\n%s\r\n%s",
                               req->path, hs, ps);
    } else {
        sreq = g_strdup_printf("GET %s?%s HTTP/1.1\r\n%s\r\n",
                               req->path, ps, hs);
    }

    g_free(len);
    g_free(ps);
    g_free(hs);

    return sreq;
}

static void steam_http_req_queue(SteamHttp *http, gboolean force)
{
    SteamHttpReq *req;
    SteamHttpReq *treq;
    gchar        *sreq;
    GList        *l;
    gboolean      ssl;

    if ((http->flags & STEAM_HTTP_FLAG_PAUSED) ||
        (!force && (http->flags & STEAM_HTTP_FLAG_QUEUED)))
        return;

    req = NULL;

    for (l = http->reqq->tail; l != NULL; l = l->prev) {
        treq = l->data;

        if (!(treq->flags & STEAM_HTTP_REQ_FLAG_QUEUED))
            continue;

        req = l->data;
        break;
    }

    if (req == NULL) {
        http->flags &= ~STEAM_HTTP_FLAG_QUEUED;
        return;
    } else {
        http->flags |= STEAM_HTTP_FLAG_QUEUED;
    }

    ssl  = (req->flags & STEAM_HTTP_REQ_FLAG_SSL);
    sreq = steam_http_req_assemble(req);

    if (G_UNLIKELY(sreq == NULL))
        return;

    req->request = http_dorequest(req->host, req->port, ssl, sreq,
                                  steam_http_req_cb, req);

    g_free(sreq);
}

void steam_http_req_send(SteamHttpReq *req)
{
    gchar    *sreq;
    gboolean  ssl;

    g_return_if_fail(req != NULL);

    if (req->flags & STEAM_HTTP_REQ_FLAG_NOFREE)
        req->flags &= ~STEAM_HTTP_REQ_FLAG_NOFREE;

    if (req->flags & STEAM_HTTP_REQ_FLAG_QUEUED) {
        g_queue_push_head(req->http->reqq, req);
        steam_http_req_queue(req->http, FALSE);
        return;
    }

    ssl  = (req->flags & STEAM_HTTP_REQ_FLAG_SSL);
    sreq = steam_http_req_assemble(req);

    if (G_UNLIKELY(sreq == NULL))
        return;

    req->request = http_dorequest(req->host, req->port, ssl, sreq,
                                  steam_http_req_cb, req);

    g_queue_push_head(req->http->reqq, req);
    g_free(sreq);
}

gchar *steam_http_uri_escape(const gchar *unescaped)
{
    gchar *ret;
    gchar *e;

    if (unescaped == NULL)
        return NULL;

    e = g_strndup(unescaped, (strlen(unescaped) * 3) + 1);
    http_encode(e);

    ret = g_strdup(e);
    g_free(e);

    return ret;
}
