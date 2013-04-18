/*
 *  megatools - Mega.co.nz client library and tools
 *  Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "http.h"
#include "config.h"
#include <curl/curl.h>
#include <string.h>

#define DEBUG_CURL 0

struct _http
{
  CURL* curl;
  GHashTable* headers;

  http_progress_fn progress_cb;
  gpointer progress_data;
};

http* http_new(void)
{
  http* h = g_new0(http, 1);

  h->curl = curl_easy_init();
  if (!h->curl)
  {
    g_free(h);
    return NULL;
  }

#if DEBUG_CURL == 1
  curl_easy_setopt(h->curl, CURLOPT_VERBOSE, 1L);
#endif

  //XXX: because we don't distribute cert database on windows
#ifdef G_OS_WIN32
  curl_easy_setopt(h->curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(h->curl, CURLOPT_SSL_VERIFYHOST, 0L);
#endif

  //XXX: don't use alarm signal to time out dns queries
  //curl_easy_setopt(h->curl, CURLOPT_NOSIGNAL, 1L);

  curl_easy_setopt(h->curl, CURLOPT_FOLLOWLOCATION, 1L);

  h->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

  // set default headers
  http_set_referer(h, "https://mega.co.nz/");
  http_set_user_agent(h, "Megatools (" VERSION ")");

  return h;
}

void http_set_header(http* h, const gchar* name, const gchar* value)
{
  g_return_if_fail(h != NULL);
  g_return_if_fail(name != NULL);
  g_return_if_fail(value != NULL);

  g_hash_table_insert(h->headers, g_strdup(name), g_strdup(value));
}

void http_set_content_type(http* h, const gchar* type)
{
  http_set_header(h, "Content-Type", type);
}

void http_set_content_length(http* h, goffset len)
{
  gchar* tmp = g_strdup_printf("%" G_GOFFSET_FORMAT, len);
  http_set_header(h, "Content-Length", tmp);
  g_free(tmp);
}

void http_no_expect(http* h)
{
  http_set_header(h, "Expect", "");
}

void http_set_referer(http* h, const gchar* referer)
{
  http_set_header(h, "Referer", referer);
}

void http_set_user_agent(http* h, const gchar* ua)
{
  http_set_header(h, "User-Agent", ua);
}

static int curl_progress(http* h, double dltotal, double dlnow, double ultotal, double ulnow)
{
  if (h->progress_cb)
  {
    if (!h->progress_cb(dltotal + ultotal, dlnow + ulnow, h->progress_data))
      return 1; // cancel
  }

  return 0;
}

void http_set_progress_callback(http* h, http_progress_fn cb, gpointer data)
{
  if (cb)
  {
    h->progress_cb = cb;
    h->progress_data = data;

    curl_easy_setopt(h->curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(h->curl, CURLOPT_PROGRESSFUNCTION, (curl_progress_callback)curl_progress);
    curl_easy_setopt(h->curl, CURLOPT_PROGRESSDATA, h);
  }
  else
  {
    curl_easy_setopt(h->curl, CURLOPT_NOPROGRESS, 1L);
  }
}

static void add_header(gchar* key, gchar* val, struct curl_slist** l)
{
  gchar* tmp = g_strdup_printf("%s: %s", key, val);
  *l = curl_slist_append(*l, tmp);
  g_free(tmp);
}

static size_t append_gstring(void *buffer, size_t size, size_t nmemb, GString *str)
{
  if (size * nmemb > 0)
    g_string_append_len(str, buffer, size * nmemb);

  return nmemb;
}

GString* http_post(http* h, const gchar* url, const gchar* body, gssize body_len, GError** err)
{
  struct curl_slist* headers = NULL;
  glong http_status = 0;
  GString* response;
  CURLcode res;

  g_return_val_if_fail(h != NULL, NULL);
  g_return_val_if_fail(url != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  // setup post headers and url
  curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
  curl_easy_setopt(h->curl, CURLOPT_URL, url);
  g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

  // pass request body
  if (body)
  {
    curl_easy_setopt(h->curl, CURLOPT_NOBODY, 0L);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, body_len);
  }
  else
  {
    curl_easy_setopt(h->curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDS, NULL);
    curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, 0L);
  }

  // prepare buffer for the response body
  response = g_string_sized_new(1024);
  curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)append_gstring);
  curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, response);

  // perform HTTP request
  res = curl_easy_perform(h->curl);

  // check the result
  if (res == CURLE_OK)
  {
    if (curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK)
    {
      if (http_status == 200)
      {
        goto out;
      }
      else
      {
        g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Server returned %ld", http_status);
      }
    }
    else
    {
      g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Can't get http status code");
    }
  }
  else if (res == CURLE_GOT_NOTHING)
  {
    g_set_error(err, HTTP_ERROR, HTTP_ERROR_NO_RESPONSE, "CURL error: %s", curl_easy_strerror(res));
  }
  else
  {
    g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "CURL error: %s", curl_easy_strerror(res));
  }

  g_string_free(response, TRUE);
  response = NULL;

out:
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
  curl_slist_free_all(headers);
  if (response)
    return response;

  return NULL;
}

struct _stream_data
{
  http_data_fn cb;
  gpointer user_data;
};

static size_t curl_read(void *buffer, size_t size, size_t nmemb, struct _stream_data* data)
{
  return data->cb(buffer, size * nmemb, data->user_data);
}

GString* http_post_stream_upload(http* h, const gchar* url, goffset len, http_data_fn read_cb, gpointer user_data, GError** err)
{
  struct curl_slist* headers = NULL;
  glong http_status = 0;
  GString* response;
  CURLcode res;
  struct _stream_data data;

  g_return_val_if_fail(h != NULL, NULL);
  g_return_val_if_fail(url != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  http_no_expect(h);

  // setup post headers and url
  curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
  curl_easy_setopt(h->curl, CURLOPT_URL, url);

  // setup request post body writer
  http_set_content_length(h, len);
  curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE_LARGE, len);

  data.cb = read_cb;
  data.user_data = user_data;
  curl_easy_setopt(h->curl, CURLOPT_READFUNCTION, (curl_read_callback)curl_read);
  curl_easy_setopt(h->curl, CURLOPT_READDATA, &data);

  // prepare buffer for the response body
  response = g_string_sized_new(512);
  curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)append_gstring);
  curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, response);

  g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

  // perform HTTP request
  res = curl_easy_perform(h->curl);

  // check the result
  if (res == CURLE_OK)
  {
    if (curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK)
    {
      if (http_status == 200)
      {
        goto out;
      }
      else
      {
        g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Server returned %ld", http_status);
      }
    }
    else
    {
      g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Can't get http status code");
    }
  }
  else if (res == CURLE_GOT_NOTHING)
  {
    g_set_error(err, HTTP_ERROR, HTTP_ERROR_NO_RESPONSE, "CURL error: %s", curl_easy_strerror(res));
  }
  else
  {
    g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "CURL error: %s", curl_easy_strerror(res));
  }

  g_string_free(response, TRUE);
  response = NULL;

out:
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
  curl_slist_free_all(headers);
  if (response)
    return response;

  return NULL;
}

static size_t curl_write(void *buffer, size_t size, size_t nmemb, struct _stream_data* data)
{
  return data->cb(buffer, size * nmemb, data->user_data);
}

static CURLcode curl_easy_perform_retry_empty(CURL* curl)
{
  gint delay = 250000; // repeat after 250ms 500ms 1s ...
  CURLcode res;

  g_return_val_if_fail(curl != NULL, CURLE_UNKNOWN_OPTION);

again:
  res = curl_easy_perform(curl);
  if (res == CURLE_GOT_NOTHING)
  {
    g_usleep(delay);
    delay = delay * 2;

    if (delay > 4 * 1000 * 1000)
      return CURLE_GOT_NOTHING;

    goto again;
  }

  return res;
}

gboolean http_post_stream_download(http* h, const gchar* url, http_data_fn write_cb, gpointer user_data, GError** err)
{
  struct curl_slist* headers = NULL;
  glong http_status = 0;
  CURLcode res;
  struct _stream_data data;
  gboolean status = FALSE;

  g_return_val_if_fail(h != NULL, FALSE);
  g_return_val_if_fail(url != NULL, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  http_no_expect(h);

  // setup post headers and url
  curl_easy_setopt(h->curl, CURLOPT_POST, 1L);
  curl_easy_setopt(h->curl, CURLOPT_URL, url);

  // request is empty
  curl_easy_setopt(h->curl, CURLOPT_POSTFIELDSIZE, 0);

  // setup response writer
  data.cb = write_cb;
  data.user_data = user_data;
  curl_easy_setopt(h->curl, CURLOPT_WRITEFUNCTION, (curl_write_callback)curl_write);
  curl_easy_setopt(h->curl, CURLOPT_WRITEDATA, &data);

  g_hash_table_foreach(h->headers, (GHFunc)add_header, &headers);
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, headers);

  // perform HTTP request
  res = curl_easy_perform_retry_empty(h->curl);
  // check the result
  if (res == CURLE_OK)
  {
    if (curl_easy_getinfo(h->curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK)
    {
      if (http_status == 200)
      {
        status = TRUE;
        goto out;
      }
      else
      {
        g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Server returned %ld", http_status);
      }
    }
    else
    {
      g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "Can't get http status code");
    }
  }
  else
  {
    g_set_error(err, HTTP_ERROR, HTTP_ERROR_OTHER, "CURL error: %s", curl_easy_strerror(res));
  }

out:
  curl_easy_setopt(h->curl, CURLOPT_HTTPHEADER, NULL);
  curl_slist_free_all(headers);
  return status;
}


void http_free(http* h)
{
  if (!h)
    return;

  g_hash_table_destroy(h->headers);
  curl_easy_cleanup(h->curl);

  memset(h, 0, sizeof(http));
  g_free(h);
}

GQuark http_error_quark(void)
{
  return g_quark_from_static_string("http-error-quark");
}
