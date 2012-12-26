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

#include <bitlbee.h>
#include <stdarg.h>
#include <string.h>

#include "steam-http.h"
#include "steam-util.h"

global_t global;

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

    http->agent  = g_strdup(agent);
    http->ddfunc = ddfunc;

    return http;
}

void steam_http_free_reqs(SteamHttp *http)
{
    g_return_if_fail(http != NULL);

    g_slist_free_full(http->requests, (GDestroyNotify) steam_http_req_free);
    http->requests = NULL;
}

void steam_http_free(SteamHttp *http)
{
    g_return_if_fail(http != NULL);

    steam_http_free_reqs(http);

    g_free(http->agent);
    g_free(http);
}

static gint steam_strcmp(gconstpointer a, gconstpointer b, gpointer data)
{
    return g_strcmp0(a, b);
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

    req->headers = g_tree_new_full(steam_strcmp, NULL, g_free, g_free);
    req->params  = g_tree_new_full(steam_strcmp, NULL, g_free, g_free);

    steam_http_req_headers_set(req, 4,
        "User-Agent", http->agent,
        "Host",       host,
        "Accept",     "*/*",
        "Connection", "Close"
    );

    return req;
}

static void steam_http_req_cb_null(struct http_request *request)
{
    /* Fake callback for http_request */
}

void steam_http_req_free(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    if (req->rsid > 0)
        b_event_remove(req->rsid);

    if (req->request != NULL) {
        req->request->func = steam_http_req_cb_null;
        req->request->data = NULL;
    }

    if ((req->ddfunc != NULL) && (req->data != NULL))
        req->ddfunc(req->data);

    if (req->err != NULL)
        g_error_free(req->err);

    g_tree_destroy(req->headers);
    g_tree_destroy(req->params);

    g_free(req->path);
    g_free(req->host);
    g_free(req);
}

void steam_http_req_headers_set(SteamHttpReq *req, gsize size, ...)
{
    va_list  ap;
    gsize    i;
    gchar   *key;
    gchar   *val;

    g_return_if_fail(req != NULL);

    if (size < 1)
        return;

    va_start(ap, size);

    for (i = 0; i < size; i++) {
        key = va_arg(ap, gchar*);
        val = va_arg(ap, gchar*);

        if ((key == NULL) || (val == NULL))
            continue;

        key = g_strdup(key);
        val = g_strdup(val);

        g_tree_insert(req->headers, key, val);
    }

    va_end(ap);
}

void steam_http_req_params_set(SteamHttpReq *req, gsize size, ...)
{
    va_list  ap;
    gsize    i;
    gchar   *key;
    gchar   *val;

    g_return_if_fail(req != NULL);

    if (size < 1)
        return;

    va_start(ap, size);

    for (i = 0; i < size; i++) {
        key = va_arg(ap, gchar*);
        val = va_arg(ap, gchar*);

        if (key == NULL)
            continue;

        key = g_uri_escape_string(key, NULL, TRUE);

        if (val != NULL)
            val = g_uri_escape_string(val, NULL, TRUE);

        g_tree_insert(req->params, key, val);
    }

    va_end(ap);
}

static gboolean steam_tree_headers(gchar *key, gchar *value, GString *gstr)
{
    if (key == NULL)
        return FALSE;

    if (value == NULL)
        value = "";

    g_string_append_printf(gstr, "%s: %s\r\n", key, value);
    return FALSE;
}

static gboolean steam_tree_params(gchar *key, gchar *value, GString *gstr)
{
    gchar *sep;

    if (key == NULL)
        return FALSE;

    if (value == NULL)
        value = "";

    sep = (gstr->len > 0) ? "&" : "";

    g_string_append_printf(gstr, "%s%s=%s", sep, key, value);
    return FALSE;
}

static gboolean steam_http_req_resend(gpointer data, gint fd,
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

    gboolean freeup;
    guint    i;

    req->http->requests = g_slist_remove(req->http->requests, req);

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
                                      steam_http_req_resend, req);
            return;
        }

        g_prefix_error(&req->err, "HTTP: ");
    }

    if (req->func != NULL)
        freeup = req->func(req, req->data);
    else
        freeup = TRUE;

    if (freeup) {
        steam_http_req_free(req);
        return;
    }

    if (req->err != NULL) {
        g_error_free(req->err);
        req->err = NULL;
    }

    req->request   = NULL;
    req->body      = NULL;
    req->body_size = 0;
    req->errc      = 0;
}

void steam_http_req_send(SteamHttpReq *req)
{
    GString *gstr;
    gchar   *sreq;
    gchar   *hs;
    gchar   *ps;
    gchar   *len;

    gboolean ssl;

    g_return_if_fail(req != NULL);

    gstr = g_string_sized_new(128);
    g_tree_foreach(req->params, (GTraverseFunc) steam_tree_params, gstr);
    len = g_strdup_printf("%" G_GSIZE_FORMAT, gstr->len);
    ps  = g_string_free(gstr, FALSE);

    if (req->flags & STEAM_HTTP_FLAG_POST) {
        steam_http_req_headers_set(req, 2,
            "Content-Type",   "application/x-www-form-urlencoded",
            "Content-Length", len
        );
    }

    gstr = g_string_sized_new(128);
    g_tree_foreach(req->headers, (GTraverseFunc) steam_tree_headers, gstr);
    hs = g_string_free(gstr, FALSE);

    if (req->flags & STEAM_HTTP_FLAG_POST) {
        sreq = g_strdup_printf("POST %s HTTP/1.1\r\n%s\r\n%s",
                               req->path, hs, ps);
    } else {
        sreq = g_strdup_printf("GET %s?%s HTTP/1.1\r\n%s\r\n",
                               req->path, ps, hs);
    }

    g_free(len);
    g_free(ps);
    g_free(hs);

    ssl = (req->flags & STEAM_HTTP_FLAG_SSL);
    req->request = http_dorequest(req->host, req->port, ssl, sreq,
                                  steam_http_req_cb, req);

    req->http->requests = g_slist_prepend(req->http->requests, req);
    g_free(sreq);
}
