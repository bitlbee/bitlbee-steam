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

global_t global;

SteamHttp *steam_http_new(const gchar *agent)
{
    SteamHttp *http;

    http = g_new0(SteamHttp, 1);
    http->agent = g_strdup(agent);

    return http;
}

static void steam_http_req_cb_null(struct http_request *request)
{
    /* Fake callback for http_request */
}

void steam_http_free_reqs(SteamHttp *http)
{
    SteamHttpReq *req;
    GSList       *l;

    g_return_if_fail(http != NULL);

    for (l = http->requests; l != NULL; l = l->next) {
        req = l->data;

        req->request->func = steam_http_req_cb_null;
        req->request->data = NULL;

        g_free(req);
    }

    g_slist_free(http->requests);
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

    req->http = http;
    req->host = g_strdup(host);
    req->port = port;
    req->path = g_strdup(path);
    req->func = func;
    req->data = data;

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

void steam_http_req_free(SteamHttpReq *req)
{
    g_return_if_fail(req != NULL);

    g_tree_destroy(req->headers);
    g_tree_destroy(req->params);

    g_free(req->host);
    g_free(req->path);
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

static gboolean steam_tree_headers(gpointer key, gpointer value, GString *gstr)
{
    if (key == NULL)
        return FALSE;

    if (value == NULL)
        value = "";

    g_string_append_printf(gstr, "%s: %s\r\n", key, value);
    return FALSE;
}

static gboolean steam_tree_params(gpointer key, gpointer value, GString *gstr)
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

static void steam_http_req_cb(struct http_request *request)
{
    SteamHttpReq  *req = request->data;
    gchar        **ls;

    gboolean freeup;
    guint    i;

    /* Shortcut some req->request values into req */
    req->errcode   = req->request->status_code;
    req->errstr    = req->request->status_string;
    req->body      = req->request->reply_body;
    req->body_size = req->request->body_size;

    if (global.conf->verbose) {
        g_print("HTTP Reply (%s): %s\n", req->path, req->errstr);

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

    if (req->func != NULL)
        freeup = req->func(req, req->data);
    else
        freeup = TRUE;

    req->http->requests = g_slist_remove(req->http->requests, req);

    if (freeup) {
        steam_http_req_free(req);
        return;
    }

    req->errcode   = 0;
    req->errstr    = NULL;
    req->body      = NULL;
    req->body_size = 0;
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
    len = g_strdup_printf("%lu", gstr->len);
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

    req->http->requests = g_slist_append(req->http->requests, req);
    g_free(sreq);
}
