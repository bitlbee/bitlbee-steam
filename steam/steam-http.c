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

#include <bitlbee.h>
#include <string.h>

#include "steam-http.h"
#include "steam-util.h"

GQuark
steam_http_error_quark(void)
{
    static GQuark q;

    if (G_UNLIKELY(q == 0)) {
        q = g_quark_from_static_string("steam-http-error-quark");
    }

    return q;
}

SteamHttp *
steam_http_new(const gchar *agent)
{
    SteamHttp *http;

    http = g_new0(SteamHttp, 1);
    http->agent = g_strdup(agent);
    http->reqs = g_hash_table_new(g_direct_hash, g_direct_equal);
    http->cookies = g_hash_table_new_full(g_str_hash,
                                          (GEqualFunc) steam_util_str_iequal,
                                          g_free, g_free);
    return http;
}

void
steam_http_free_reqs(SteamHttp *http)
{
    GHashTableIter iter;
    gpointer key;

    if (G_UNLIKELY(http == NULL)) {
        return;
    }

    g_hash_table_iter_init(&iter, http->reqs);

    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        g_hash_table_iter_remove(&iter);
        steam_http_req_free(key);
    }
}

void
steam_http_free(SteamHttp *http)
{
    if (G_UNLIKELY(http == NULL)) {
        return;
    }

    steam_http_free_reqs(http);
    g_hash_table_destroy(http->reqs);
    g_hash_table_destroy(http->cookies);

    g_free(http->agent);
    g_free(http);
}

static void
steam_http_tree_ins(GHashTable *table, const SteamHttpPair *pair, va_list ap)
{
    const SteamHttpPair *p;
    gchar *key;
    gchar *val;

    for (p = pair; p != NULL; ) {
        if (p->key == NULL) {
            continue;
        }

        key = g_strdup(p->key);
        val = g_strdup(p->val);

        g_hash_table_replace(table, key, val);
        p = va_arg(ap, const SteamHttpPair*);
    }
}

const gchar *
steam_http_cookies_get(SteamHttp *http, const gchar *name)
{
    g_return_val_if_fail(http != NULL, NULL);

    return g_hash_table_lookup(http->cookies, name);
}

void
steam_http_cookies_set(SteamHttp *http, const SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(http != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(http->cookies, pair, ap);
    va_end(ap);
}

void
steam_http_cookies_parse_req(SteamHttp *http, const SteamHttpReq *req)
{
    gchar **hdrs;
    gchar **kv;
    gchar *str;
    gsize i;
    gsize j;

    g_return_if_fail(http != NULL);
    g_return_if_fail(req != NULL);

    if (req->request == NULL) {
        return;
    }

    hdrs = g_strsplit(req->request->reply_headers, "\r\n", 0);

    for (i = 0; hdrs[i] != NULL; i++) {
        if (g_ascii_strncasecmp(hdrs[i], "Set-Cookie", 10) != 0) {
            continue;
        }

        str = strchr(hdrs[i], ';');

        if (str != NULL) {
            str[0] = 0;
        }

        str = strchr(hdrs[i], ':');

        if (str == NULL) {
            continue;
        }

        str = g_strstrip(++str);
        kv = g_strsplit(str, "=", 2);

        for (j = 0; kv[j] != NULL; j++) {
            str = steam_http_uri_unescape(kv[j]);
            g_free(kv[j]);
            kv[j] = str;
        }

        if (g_strv_length(kv) > 1) {
            steam_http_cookies_set(http, STEAM_HTTP_PAIR(kv[0], kv[1]), NULL);
        }

        g_strfreev(kv);
    }

    g_strfreev(hdrs);
}

void
steam_http_cookies_parse_str(SteamHttp *http, const gchar *data)
{
    gchar **ckis;
    gchar **kv;
    gchar *str;
    gsize i;
    gsize j;

    g_return_if_fail(http != NULL);
    g_return_if_fail(data != NULL);

    ckis = g_strsplit(data, ";", 0);

    for (i = 0; ckis[i] != NULL; i++) {
        str = g_strstrip(ckis[i]);
        kv = g_strsplit(str, "=", 2);

        for (j = 0; kv[j] != NULL; j++) {
            str = steam_http_uri_unescape(kv[j]);
            g_free(kv[j]);
            kv[j] = str;
        }

        if (g_strv_length(kv) > 1) {
            steam_http_cookies_set(http, STEAM_HTTP_PAIR(kv[0], kv[1]), NULL);
        }

        g_strfreev(kv);
    }

    g_strfreev(ckis);
}

gchar *
steam_http_cookies_str(SteamHttp *http)
{
    gchar *key;
    gchar *str;
    gchar *val;
    GHashTableIter iter;
    GString *gstr;

    g_return_val_if_fail(http != NULL, NULL);

    gstr = g_string_sized_new(128);
    g_hash_table_iter_init(&iter, http->cookies);

    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
        if (val == NULL) {
            val = "";
        }

        key = steam_http_uri_escape(key);
        val = steam_http_uri_escape(val);

        str = (gstr->len > 0) ? "; " : "";
        g_string_append_printf(gstr, "%s%s=%s", str, key, val);

        g_free(key);
        g_free(val);
    }

    str = g_strdup(gstr->str);
    g_string_free(gstr, TRUE);
    return str;
}

SteamHttpReq *
steam_http_req_new(SteamHttp *http, const gchar *host, gint port,
                   const gchar *path, SteamHttpFunc func, gpointer data)
{
    SteamHttpReq *req;

    req = g_new0(SteamHttpReq, 1);
    req->http = http;
    req->host = g_strdup(host);
    req->port = port;
    req->path = g_strdup(path);
    req->func = func;
    req->data = data;

    req->headers = g_hash_table_new_full(g_str_hash,
                                         (GEqualFunc) steam_util_str_iequal,
                                         g_free, g_free);
    req->params = g_hash_table_new_full(g_str_hash,
                                         (GEqualFunc) steam_util_str_iequal,
                                         g_free, g_free);

    steam_http_req_headers_set(req,
        STEAM_HTTP_PAIR("User-Agent", http->agent),
        STEAM_HTTP_PAIR("Host", host),
        STEAM_HTTP_PAIR("Accept", "*/*"),
        STEAM_HTTP_PAIR("Connection", "Close"),
        NULL
    );

    return req;
}

static void
steam_http_req_close_nuller(struct http_request *request)
{

}

static void
steam_http_req_close(SteamHttpReq *req, gboolean callback)
{
    g_return_if_fail(req != NULL);
    b_event_remove(req->toid);

    if ((req->err == NULL) && (req->scode == 0)) {
        g_set_error(&req->err, STEAM_HTTP_ERROR, STEAM_HTTP_ERROR_CLOSED,
                    "Request closed");
    }

    if (callback && (req->func != NULL)) {
        req->func(req, req->data);
    }

    if (req->request != NULL) {
        /* Prevent more than one call to request->func() */
        req->request->func = steam_http_req_close_nuller;
        req->request->data = NULL;

        if (!(req->request->flags & STEAM_HTTP_CLIENT_FREED)) {
            http_close(req->request);
        }
    }

    req->status = NULL;
    req->scode = 0;
    req->header = NULL;
    req->body = NULL;
    req->body_size = 0;
    req->toid = 0;
    req->request = NULL;
}

void
steam_http_req_free(SteamHttpReq *req)
{
    if (G_UNLIKELY(req == NULL)) {
        return;
    }

    steam_http_req_close(req, TRUE);

    if (req->err != NULL) {
        g_error_free(req->err);
    }

    g_hash_table_destroy(req->headers);
    g_hash_table_destroy(req->params);

    g_free(req->path);
    g_free(req->host);
    g_free(req);
}

static void
steam_http_req_debug(SteamHttpReq *req, gboolean response,
                     const gchar *header, const gchar *body)
{
    const gchar *act;
    const gchar *prot;
    const gchar *type;
    gchar **ls;
    gchar *str;
    guint i;

    if (req->err != NULL) {
        str = g_strdup_printf(" (%s)", req->err->message);
    } else if (req->status != NULL) {
        str = g_strdup_printf(" (%s)", req->status);
    } else {
        str = g_strdup("");
    }

    act = response ? "Response" : "Request";
    type = (req->flags & STEAM_HTTP_REQ_FLAG_POST) ? "POST" : "GET";
    prot = (req->flags & STEAM_HTTP_REQ_FLAG_SSL) ? "https" : "http";

    steam_util_debug_info("%s %s (%p): %s://%s:%d%s%s", type, act, req,
                          prot, req->host, req->port, req->path, str);
    g_free(str);

    if (req->rsc > 0) {
        steam_util_debug_info("Reattempt: #%u", req->rsc);
    }

    if ((header != NULL) && (strlen(header) > 0)) {
        ls = g_strsplit(header, "\n", 0);

        for (i = 0; ls[i] != NULL; i++) {
            steam_util_debug_info(" %s", ls[i]);
        }

        g_strfreev(ls);
    } else {
        steam_util_debug_info(" ** No header data **");
        steam_util_debug_info("%s", "");
    }

    if ((body != NULL) && (strlen(body) > 0)) {
        ls = g_strsplit(body, "\n", 0);

        for (i = 0; ls[i] != NULL; i++) {
            steam_util_debug_info(" %s", ls[i]);
        }

        g_strfreev(ls);
    } else {
        steam_util_debug_info(" ** No body data **");
    }
}

void
steam_http_req_headers_set(SteamHttpReq *req, const SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(req->headers, pair, ap);
    va_end(ap);
}

void
steam_http_req_params_set(SteamHttpReq *req, const SteamHttpPair *pair, ...)
{
    va_list ap;

    g_return_if_fail(req != NULL);

    va_start(ap, pair);
    steam_http_tree_ins(req->params, pair, ap);
    va_end(ap);
}

static gboolean
steam_http_req_done_error(gpointer data, gint fd, b_input_condition cond)
{
    SteamHttpReq *req = data;
    steam_http_req_send(req);
    return FALSE;
}

static void
steam_http_req_done(SteamHttpReq *req)
{
    steam_http_req_debug(req, TRUE, req->header, req->body);

    if (req->err != NULL) {
        if (req->rsc < STEAM_HTTP_RESEND_MAX) {
            steam_http_req_close(req, FALSE);
            g_error_free(req->err);
            req->err = NULL;

            req->toid = b_timeout_add(STEAM_HTTP_RESEND_TIMEOUT,
                                      steam_http_req_done_error, req);
            req->rsc++;
            return;
        }

        g_prefix_error(&req->err, "HTTP: ");
    }

    g_hash_table_remove(req->http->reqs, req);
    steam_http_req_free(req);
}

static void
steam_http_req_cb(struct http_request *request)
{
    SteamHttpReq *req = request->data;

    /* Shortcut request elements */
    req->status = request->status_string;
    req->scode = request->status_code;
    req->header = request->reply_headers;
    req->body = request->reply_body;
    req->body_size = request->body_size;

    switch (req->scode) {
    case 200:
    case 301:
    case 302:
    case 303:
    case 307:
        break;

    default:
        g_set_error(&req->err, STEAM_HTTP_ERROR, req->scode, "%s", req->status);
    }

    req->request->flags |= STEAM_HTTP_CLIENT_FREED;
    steam_http_req_done(req);
}

static gboolean
steam_http_req_send_timeout(gpointer data, gint fd,
                                            b_input_condition cond)
{
    SteamHttpReq *req = data;

    g_set_error(&req->err, STEAM_HTTP_ERROR, STEAM_HTTP_ERROR_TIMEOUT,
                "Request timed out");

    req->toid = 0;
    steam_http_req_done(req);
    return FALSE;
}

static void
steam_http_req_asm(SteamHttpReq *req, gchar **hs, gchar **ps, gchar **fs)
{
    gchar *key;
    gchar *str;
    gchar *val;
    GHashTableIter iter;
    GString *hgs;
    GString *pgs;

    g_hash_table_iter_init(&iter, req->params);
    pgs = g_string_sized_new(128);

    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
        if (val == NULL) {
            val = "";
        }

        key = steam_http_uri_escape(key);
        val = steam_http_uri_escape(val);

        str = (pgs->len > 0) ? "&" : "";
        g_string_append_printf(pgs, "%s%s=%s", str, key, val);

        g_free(key);
        g_free(val);
    }

    if (g_hash_table_size(req->http->cookies) > 0) {
        str = steam_http_cookies_str(req->http);
        steam_http_req_headers_set(req, STEAM_HTTP_PAIR("Cookie", str), NULL);
        g_free(str);
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        str = g_strdup_printf("%" G_GSIZE_FORMAT, pgs->len);

        steam_http_req_headers_set(req,
            STEAM_HTTP_PAIR("Content-Type", "application/"
                                              "x-www-form-urlencoded"),
            STEAM_HTTP_PAIR("Content-Length", str),
            NULL
        );

        g_free(str);
    }

    g_hash_table_iter_init(&iter, req->headers);
    hgs = g_string_sized_new(128);

    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &val)) {
        if (val == NULL) {
            val = "";
        }

        g_string_append_printf(hgs, "%s: %s\r\n", key, val);
    }

    if (req->flags & STEAM_HTTP_REQ_FLAG_POST) {
        *fs = g_strdup_printf("POST %s HTTP/1.1\r\n%s\r\n%s",
                              req->path, hgs->str, pgs->str);
    } else {
        *fs = g_strdup_printf("GET %s?%s HTTP/1.1\r\n%s\r\n",
                              req->path, pgs->str, hgs->str);
    }

    *hs = g_string_free(hgs, FALSE);
    *ps = g_string_free(pgs, FALSE);
}

void
steam_http_req_send(SteamHttpReq *req)
{
    gchar *hs;
    gchar *ps;
    gchar *str;

    g_return_if_fail(req != NULL);
    steam_http_req_asm(req, &hs, &ps, &str);
    steam_http_req_debug(req, FALSE, hs, ps);

    req->request = http_dorequest(req->host, req->port,
                                  (req->flags & STEAM_HTTP_REQ_FLAG_SSL),
                                  str, steam_http_req_cb, req);
    g_hash_table_replace(req->http->reqs, req, req);

    g_free(hs);
    g_free(ps);
    g_free(str);

    if (G_UNLIKELY(req->request == NULL)) {
        g_set_error(&req->err, STEAM_HTTP_ERROR, STEAM_HTTP_ERROR_INIT,
                    "Failed to init request");
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

gchar *
steam_http_uri_escape(const gchar *unescaped)
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

gchar *
steam_http_uri_unescape(const gchar *escaped)
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

gchar *
steam_http_uri_join(const gchar *first, ...)
{
    const gchar *s;
    GString *ret;
    va_list ap;

    g_return_val_if_fail(first != NULL, NULL);

    ret = g_string_new(first);
    va_start(ap, first);
    s = va_arg(ap, const gchar *);

    while (s != NULL) {
        if ((ret->len > 0) && (ret->str[ret->len - 1] != '/')) {
            g_string_append_c(ret, '/');
        }

        g_string_append(ret, s);
        s = va_arg(ap, const gchar *);
    }

    va_end(ap);
    return g_string_free(ret, FALSE);
}
