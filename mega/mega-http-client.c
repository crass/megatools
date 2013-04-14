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

/**
 * MegaHttpClient:
 *
 * Simple HTTP client with support for:
 *
 *   - TLS/SSL
 *   - Persistent connections whenever possible
 *   - Gio streams API
 *   - Automatic error recovery
 *
 * Note that you can't have multiple requests at once in one http client.
 * If you want to make multiple connections at once, create multiple HTTP
 * clients.
 *
 * After non HTTP error, the client will restart the connection for the next 
 * request.
 */

#include <stdlib.h>
#include <string.h>
#include "mega-http-client.h"
#include "mega-http-io-stream.h"

#define MB (1024 * 1024)

enum 
{
  // no request is being performed
  CONN_STATE_NONE,

  // request was initiated from the API (no headers or data were sent yet,
  // socket is connected)
  CONN_STATE_INIT_CONNECTED,
  CONN_STATE_HEADERS_SENT, // headers sent, sending body
  CONN_STATE_BODY_SENT,
  CONN_STATE_HEADERS_RECEIVED, // headers received, receinving body
  CONN_STATE_NONE_CONNECTED,

  // failed state, connection is closed
  CONN_STATE_FAILED
};

struct _MegaHttpClientPrivate
{
  GSocketClient* client;
  GHashTable* request_headers;
  GHashTable* response_headers;

  // connection
  GSocketConnection* conn;
  GInputStream* istream;
  GOutputStream* ostream;

  // url
  GRegex* regex_url;
  gchar* resource;
  gchar* host;
  gboolean https;
  guint16 port;

  // http
  GRegex* regex_status;

  // state proeprties
  gint conn_state;
  gint64 request_length;
  gint64 response_length;
  gint64 expected_write_count;
  gint64 expected_read_count;

  gboolean needs_reconnect;
};

// {{{ GObject property and signal enums

enum MegaHttpClientProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaHttpClientSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

static gboolean parse_url(MegaHttpClient* http_client, const gchar* url, gboolean* https, gchar** host, guint16* port, gchar** resource)
{
  GMatchInfo *match_info = NULL;
  gchar* schema = NULL;
  gchar* port_str = NULL;
  gboolean status = FALSE;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(url != NULL, FALSE);
  g_return_val_if_fail(https != NULL, FALSE);
  g_return_val_if_fail(host != NULL, FALSE);
  g_return_val_if_fail(port != NULL, FALSE);
  g_return_val_if_fail(resource != NULL, FALSE);

  if (!g_regex_match(http_client->priv->regex_url, url, 0, &match_info))
    goto out;
  
  // check schema
  schema = g_match_info_fetch(match_info, 1);
  if (!g_ascii_strcasecmp("http", schema))
  {
    *port = 80;
    *https = FALSE;
  }
  else if (!g_ascii_strcasecmp("https", schema))
  {
    *port = 443;
    *https = TRUE;
  }
  else
    goto out;
  
  *host = g_match_info_fetch(match_info, 2);

  port_str = g_match_info_fetch(match_info, 3);
  if (port_str)
  {
    if (*port_str)
      *port = atoi(port_str);
    g_free(port_str);
  }

  *resource = g_match_info_fetch(match_info, 4);
  if (*resource == NULL)
    *resource = g_strdup("/");

  status = TRUE;
out:
  g_free(schema);
  g_match_info_free(match_info);
  return status;
}

static void do_disconnect(MegaHttpClient* http_client)
{
  g_return_if_fail(MEGA_IS_HTTP_CLIENT(http_client));

  MegaHttpClientPrivate* priv = http_client->priv;

  if (priv->istream)
    g_object_unref(priv->istream);

  if (priv->ostream)
    g_object_unref(priv->ostream);

  if (priv->conn)
    g_object_unref(priv->conn);

  priv->conn = NULL;
  priv->istream = NULL;
  priv->ostream = NULL;
}

static gboolean do_connect(MegaHttpClient* http_client, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  MegaHttpClientPrivate* priv = http_client->priv;

  do_disconnect(http_client);

  // enable/disable TLS
  if (priv->https)
  {
    if (!g_tls_backend_supports_tls(g_tls_backend_get_default())) 
    {
      g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "TLS backend not found, please install glib-networking.");
      return FALSE;
    }

    g_socket_client_set_tls(priv->client, TRUE);

    //XXX: insecure
    g_socket_client_set_tls_validation_flags(priv->client, G_TLS_CERTIFICATE_VALIDATE_ALL & ~G_TLS_CERTIFICATE_UNKNOWN_CA & ~G_TLS_CERTIFICATE_BAD_IDENTITY);
  }
  else
  {
    g_socket_client_set_tls(priv->client, FALSE);
  }


  priv->conn = g_socket_client_connect_to_host(priv->client, priv->host, priv->port, cancellable, &local_err);
  if (!priv->conn)
  {
    g_propagate_prefixed_error(err, local_err, "Connection failed: ");
    return FALSE;
  }
  
  GDataInputStream* data_stream = g_data_input_stream_new(g_io_stream_get_input_stream(G_IO_STREAM(http_client->priv->conn)));
  g_data_input_stream_set_newline_type(data_stream, G_DATA_STREAM_NEWLINE_TYPE_ANY);

  priv->istream = G_INPUT_STREAM(data_stream);
  priv->ostream = g_object_ref(g_io_stream_get_output_stream(G_IO_STREAM(http_client->priv->conn)));

  return TRUE;
}

static gboolean parse_http_status(MegaHttpClient* http_client, const gchar* line, gint* status, gchar** message)
{
  MegaHttpClientPrivate* priv = http_client->priv;
  GMatchInfo *match_info = NULL;

  if (g_regex_match(priv->regex_status, line, 0, &match_info))
  {
    if (status)
    {
      gchar* status_str = g_match_info_fetch(match_info, 2);
      *status = atoi(status_str);
      g_free(status_str);
    }

    if (message)
      *message = g_match_info_fetch(match_info, 3);

    g_match_info_free(match_info);
    return TRUE;
  }

  g_match_info_free(match_info);
  return FALSE;
}

static gboolean server_wants_to_close(MegaHttpClient* http_client)
{
  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);

  const gchar* connection = g_hash_table_lookup(http_client->priv->response_headers, "Connection");

  return !connection || g_ascii_strcasecmp(connection, "close") == 0;
}

static gboolean do_receive_headers(MegaHttpClient* http_client, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;
  gboolean got_content_length = FALSE;
  gint line = 0;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  MegaHttpClientPrivate* priv = http_client->priv;

  g_hash_table_remove_all(priv->response_headers);

  while (TRUE)
  {
    gchar* header = g_data_input_stream_read_line(G_DATA_INPUT_STREAM(priv->istream), NULL, cancellable, &local_err);
    if (header == NULL)
    {
      g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN, "Can't read response headers: %s", local_err ? local_err->message : "unknown error");
      g_clear_error(&local_err);
      goto err;
    }

    if (line == 0)
    {
      gint status;
      gchar* message;

      if (!parse_http_status(http_client, header, &status, &message))
      {
        g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Can't read response status: %s", header);
        g_free(header);
        goto err;
      }

      if (status != 200 && status != 201)
      {
        g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Server returned status %d: %s", status, message);
        g_free(header);
        g_free(message);
        goto err;
      }

      g_free(message);
    }
    else
    {
      if (*header == '\0')
      {
        // end of header
        g_free(header);
        break;
      }
      else
      {
        gchar* colon = strchr(header, ':');
        if (colon)
        {
          *colon = '\0';

          gchar* name = g_strstrip(g_ascii_strdown(header, -1));
          gchar* value = g_strstrip(g_strdup(colon + 1));

          if (!strcmp(name, "content-length"))
          {
            priv->expected_read_count = atoi(value);
            priv->response_length = priv->expected_read_count;
            got_content_length = TRUE;
          }

          g_hash_table_insert(http_client->priv->response_headers, name, value);
        }
        else
        {
          g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Invalid response header: %s", header);
          g_free(header);
          goto err;
        }
      }
    }

    g_free(header);
    line++;
  }

  if (!got_content_length)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "We need content length from the server!");
    goto err;
  }

  return TRUE;

err:
  return FALSE;
}

static void add_header(const gchar* key, const gchar* value, GString* headers)
{
  g_string_append_printf(headers, "%s: %s\r\n", key, value);
}

static gboolean do_send_headers(MegaHttpClient* http_client, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;
  GString* headers;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  MegaHttpClientPrivate* priv = http_client->priv;

  headers = g_string_sized_new(300);

  mega_http_client_set_header(http_client, "Host", priv->host);
  mega_http_client_set_content_length(http_client, priv->expected_write_count);

  g_string_append_printf(headers, "%s %s HTTP/1.1\r\n", "POST", priv->resource);
  g_hash_table_foreach(priv->request_headers, (GHFunc)add_header, headers);
  g_string_append(headers, "\r\n");

  gboolean rs = g_output_stream_write_all(priv->ostream, headers->str, headers->len, NULL, cancellable, &local_err);
  if (!rs)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN, "Can't write request headers: %s", local_err ? local_err->message : "unknown error");
    g_clear_error(&local_err);
  }

  g_string_free(headers, TRUE);

  return rs;
}

/*
 * HTTP client state machine:
 *
 * API can request only certain state transitions, others will result in error.
 *
 *  - none -> init-connected
 *  - none-connected -> init-connected
 *  - init-connected -> headers-sent -> body-sent -> headers-received   (any combinations in the right direction)
 *  - headers-received -> (none | none-connected)
 *  - [any] -> none
 *  - [any] -> failed
 *
 *  Any other requests will fail.
 *
 *  Also depending on the number of bytes read/written some transitions may
 *  fail.
 */
static gboolean goto_state(MegaHttpClient* http_client, gint target_state, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(target_state >= CONN_STATE_NONE && target_state <= CONN_STATE_FAILED, FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  MegaHttpClientPrivate* priv = http_client->priv;

  //g_print("GOTO %d -> %d\n", priv->conn_state, target_state);

  // we can always transition to NONE/FAILED states by disconnecting
  if (target_state == CONN_STATE_NONE || target_state == CONN_STATE_FAILED)
  {
    do_disconnect(http_client);
    priv->conn_state = target_state;
    return TRUE;
  }

  // perform connection
  if (target_state == CONN_STATE_INIT_CONNECTED)
  {
    if (priv->conn_state != CONN_STATE_NONE && priv->conn_state != CONN_STATE_NONE_CONNECTED && priv->conn_state != CONN_STATE_FAILED)
    {
      g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Can't connect now");
      goto err;
    }

    if (priv->conn_state == CONN_STATE_NONE || priv->conn_state == CONN_STATE_FAILED)
    {
      if (!do_connect(http_client, cancellable, &local_err))
      {
        g_propagate_error(err, local_err);
        goto err;
      }
    }

    priv->conn_state = target_state;
    return TRUE;
  }

  // we can't do nothing else in a failed state
  if (priv->conn_state == CONN_STATE_FAILED)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Request is in the failed state");
    goto err;
  }

  // we can get from NONE and NONE_CONNECTED only to INIT_CONNECTED by direct
  // request
  if (priv->conn_state == CONN_STATE_NONE_CONNECTED || priv->conn_state == CONN_STATE_NONE)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "There's no request being done!");
    goto err;
  }

  // possible start states: INIT_CONNECTED, HEADERS_SENT, BODY_SENT, HEADERS_RECEIVED
  // possible target states: HEADERS_SENT, BODY_SENT, HEADERS_RECEIVED, NONE_CONNECTED

  // check direction of the request
  if (target_state < priv->conn_state)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Unsupported state transition!");
    goto err;
  }

  // loop until we reach a desired state or error
  while (priv->conn_state != target_state)
  {
    // move to the next state if possible, otherwise err out
    if (priv->conn_state == CONN_STATE_INIT_CONNECTED)
    {
      if (!do_send_headers(http_client, cancellable, &local_err))
      {
        g_propagate_error(err, local_err);
        goto err;
      }

      priv->conn_state = CONN_STATE_HEADERS_SENT;
    }
    else if (priv->conn_state == CONN_STATE_HEADERS_SENT)
    {
      if (priv->expected_write_count != 0)
      {
        g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Request body is not finished");
        goto err;
      }

      priv->conn_state = CONN_STATE_BODY_SENT;
    }
    else if (priv->conn_state == CONN_STATE_BODY_SENT)
    {
      if (!do_receive_headers(http_client, cancellable, &local_err))
      {
        g_propagate_error(err, local_err);
        goto err;
      }

      priv->conn_state = CONN_STATE_HEADERS_RECEIVED;
    }
    else if (priv->conn_state == CONN_STATE_HEADERS_RECEIVED)
    {
      if (priv->expected_read_count != 0)
      {
        g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Response body is not finished");
        goto err;
      }

      priv->conn_state = CONN_STATE_NONE_CONNECTED;
    }
    else
    {
      g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Unhandled state: %d", priv->conn_state);
      goto err;
    }
  }

  return TRUE;

err:
  do_disconnect(http_client);
  priv->conn_state = CONN_STATE_FAILED;
  return FALSE;
}

GQuark mega_http_client_error_quark(void)
{
  return g_quark_from_static_string("mega-http-client-error-quark");
}

/**
 * mega_http_client_new:
 *
 * Create new #MegaHttpClient object.
 *
 * Returns: #MegaHttpClient object.
 */
MegaHttpClient* mega_http_client_new(void)
{
  MegaHttpClient *http_client = g_object_new(MEGA_TYPE_HTTP_CLIENT, NULL);

  return http_client;
}

/**
 * mega_http_client_set_header:
 * @http_client: a #MegaHttpClient
 * @name: Header name (case sensitive)
 * @value: (allow-none): Header value. Pass null to remove the header.
 *
 * Set request header.
 */
void mega_http_client_set_header(MegaHttpClient* http_client, const gchar* name, const gchar* value)
{
  g_return_if_fail(MEGA_IS_HTTP_CLIENT(http_client));
  g_return_if_fail(name != NULL);

  if (value)
    g_hash_table_insert(http_client->priv->request_headers, g_strdup(name), g_strdup(value));
  else
    g_hash_table_remove(http_client->priv->request_headers, name);
}

/**
 * mega_http_client_set_content_type:
 * @http_client: a #MegaHttpClient
 * @content_type: Content type.
 *
 * Set content type header.
 */
void mega_http_client_set_content_type(MegaHttpClient* http_client, const gchar* content_type)
{
  g_return_if_fail(MEGA_IS_HTTP_CLIENT(http_client));
  g_return_if_fail(content_type != NULL);

  mega_http_client_set_header(http_client, "Content-Type", content_type);
}

/**
 * mega_http_client_set_content_length:
 * @http_client: a #MegaHttpClient
 * @content_length: Content length.
 *
 * Set content length header.
 */
void mega_http_client_set_content_length(MegaHttpClient* http_client, guint64 content_length)
{
  g_return_if_fail(MEGA_IS_HTTP_CLIENT(http_client));

  gchar* tmp = g_strdup_printf("%" G_GUINT64_FORMAT, content_length);
  mega_http_client_set_header(http_client, "Content-Length", tmp);
  g_free(tmp);
}

/**
 * mega_http_client_post:
 * @http_client: a #MegaHttpClient
 * @url: URL to make the POST to.
 * @request_length: Length of the request body.
 * @err: Error.
 *
 * Start a new POST request.
 *
 * Returns: (transfer full): IO stream you'd use to write request body and read
 * response.
 */
MegaHttpIOStream* mega_http_client_post(MegaHttpClient* http_client, const gchar* url, gint64 request_length, GError** err)
{
  GError* local_err = NULL;
  gchar* host = NULL;
  gchar* resource = NULL;
  guint16 port = 80;
  gboolean https = FALSE;
  gboolean reconnect = FALSE;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), NULL);
  g_return_val_if_fail(url != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  MegaHttpClientPrivate* priv = http_client->priv;

  // parse URL
  if (!parse_url(http_client, url, &https, &host, &port, &resource))
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Invalid URL: %s", url);
    return NULL;
  }

  // check that there is a change in host or https flag
  if (priv->host == NULL || g_ascii_strcasecmp(priv->host, host) || priv->https != https || priv->port != port) 
  {
    g_free(priv->host);
    priv->host = host;
    priv->https = https;
    priv->port = port;

    // host/port/ssl changed, reconnection is necessary
    goto_state(http_client, CONN_STATE_NONE, NULL, NULL);
  }

  g_free(priv->resource);
  priv->resource = resource;

  if (!goto_state(http_client, CONN_STATE_INIT_CONNECTED, NULL, &local_err))
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  priv->request_length = request_length;
  priv->expected_write_count = request_length;
  priv->expected_read_count = -1;
  priv->response_length = -1;

  return mega_http_io_stream_new(http_client);
}

/**
 * mega_http_client_post_simple:
 * @http_client: a #MegaHttpClient
 * @url: URL to make the POST to.
 * @body: (in) (element-type guint8) (array length=body_len) (transfer none): POST request body.
 * @body_len: Length of the POST request body.
 * @err: Error.
 *
 * Make a POST request. Simplified interface.
 *
 * Returns: (transfer full): Response body.
 */
GString* mega_http_client_post_simple(MegaHttpClient* http_client, const gchar* url, const gchar* body, gssize body_len, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), NULL);
  g_return_val_if_fail(url != NULL, NULL);
  g_return_val_if_fail(body != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  MegaHttpClientPrivate* priv = http_client->priv;

  body_len = body_len >= 0 ? body_len : strlen(body);

  MegaHttpIOStream* io = mega_http_client_post(http_client, url, body_len, &local_err);
  if (!io) 
  {
    g_propagate_error(err, local_err);
    return NULL;
  }

  GInputStream* is = g_io_stream_get_input_stream(G_IO_STREAM(io));
  GOutputStream* os = g_io_stream_get_output_stream(G_IO_STREAM(io));

  if (body_len > 0)
  {
    if (!g_output_stream_write_all(os, body, body_len, NULL, NULL, &local_err))
    {
      g_propagate_error(err, local_err);
      g_object_unref(io);
      return NULL;
    }
  }

  if (!goto_state(http_client, CONN_STATE_HEADERS_RECEIVED, NULL, &local_err))
  {
    g_propagate_error(err, local_err);
    g_object_unref(io);
    return NULL;
  }

  gint64 response_length = mega_http_client_get_response_length(http_client, NULL, &local_err);
  if (response_length < 0)
  {
    g_propagate_prefixed_error(err, local_err, "Response length not set: ");
    g_object_unref(io);
    return NULL;
  }

  if (response_length > 32 * MB) 
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Response length over 32 MiB not supported (for post_simple): %s", url);
    g_object_unref(io);
    return NULL;
  }

  gsize len = (gsize)response_length;

  GString* response = g_string_sized_new(len);

  if (len > 0)
  {
    if (!g_input_stream_read_all(is, response->str, len, &response->len, NULL, &local_err))
    {
      g_propagate_error(err, local_err);
      g_string_free(response, TRUE);
      g_object_unref(io);
      return NULL;
    }

    if (len != response->len)
    {
      g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Can't read the entire response: %s", url);
      g_string_free(response, TRUE);
      g_object_unref(io);
      return NULL;
    }

    response->str[response->len] = '\0';
  }

  g_object_unref(io);
  return response;
}

/**
 * mega_http_client_write:
 * @http_client: a #MegaHttpClient
 * @buffer: 
 * @count: 
 * @cancellable: 
 * @err: 
 *
 * Description...
 *
 * Returns: 
 */
gssize mega_http_client_write(MegaHttpClient* http_client, const guchar* buffer, gsize count, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), -1);
  g_return_val_if_fail(buffer != NULL, -1);
  g_return_val_if_fail(count > 0, -1);
  g_return_val_if_fail(err == NULL || *err == NULL, -1);

  MegaHttpClientPrivate* priv = http_client->priv;

  if (!goto_state(http_client, CONN_STATE_HEADERS_SENT, cancellable, &local_err))
  {
    g_propagate_error(err, local_err);
    return -1;
  }

  if (priv->expected_write_count >= 0 && count > priv->expected_write_count)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Write of %" G_GSIZE_FORMAT " too big, expected at most: %" G_GINT64_FORMAT, count, priv->expected_write_count);
    return -1;
  }

  gssize bytes_written = g_output_stream_write(priv->ostream, buffer, count, cancellable, &local_err);
  if (bytes_written >= 0)
  {
    if (priv->expected_write_count >= 0)
      priv->expected_write_count -= bytes_written;
  }

  if (bytes_written < 0)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN, "Can't write request: %s", local_err ? local_err->message : "unknown error");
    g_clear_error(&local_err);
    goto_state(http_client, CONN_STATE_FAILED, NULL, NULL);
  }

  return bytes_written;
}

/**
 * mega_http_client_read:
 * @http_client: a #MegaHttpClient
 * @buffer: 
 * @count: 
 * @cancellable: 
 * @err: 
 *
 * Description...
 *
 * Returns: 
 */
gssize mega_http_client_read(MegaHttpClient* http_client, guchar* buffer, gsize count, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), -1);
  g_return_val_if_fail(buffer != NULL, -1);
  g_return_val_if_fail(count > 0, -1);
  g_return_val_if_fail(err == NULL || *err == NULL, -1);

  MegaHttpClientPrivate* priv = http_client->priv;

  if (!goto_state(http_client, CONN_STATE_HEADERS_RECEIVED, cancellable, &local_err))
  {
    g_propagate_error(err, local_err);
    return -1;
  }

  gint end_state = server_wants_to_close(http_client) ? CONN_STATE_NONE : CONN_STATE_NONE_CONNECTED;

  // end of stream
  if (priv->expected_read_count == 0)
  {
    if (!goto_state(http_client, end_state, cancellable, &local_err))
    {
      g_propagate_error(err, local_err);
      return -1;
    }

    return 0;
  }

  // read at most expected read count if set
  if (priv->expected_read_count > 0 && count > priv->expected_read_count)
    count = priv->expected_read_count;

  // do the reading
  gssize bytes_read = g_input_stream_read(priv->istream, buffer, count, cancellable, &local_err);
  if (bytes_read >= 0)
  {
    if (priv->expected_read_count > 0)
      priv->expected_read_count -= bytes_read;
  }

  if (priv->expected_read_count == 0)
  {
    if (!goto_state(http_client, end_state, cancellable, &local_err))
    {
      g_propagate_error(err, local_err);
      return -1;
    }
  }

  if (bytes_read < 0)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN, "Can't read response: %s", local_err ? local_err->message : "unknown error");
    g_clear_error(&local_err);
    goto_state(http_client, CONN_STATE_FAILED, NULL, NULL);
  }

  return bytes_read;
}

/**
 * mega_http_client_close:
 * @http_client: a #MegaHttpClient
 * @cancellable: 
 * @err: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_http_client_close(MegaHttpClient* http_client, gboolean force, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), FALSE);
  g_return_val_if_fail(err == NULL || *err == NULL, FALSE);

  MegaHttpClientPrivate* priv = http_client->priv;

  if (priv->conn_state == CONN_STATE_NONE_CONNECTED && !force)
    return TRUE;

  if (!goto_state(http_client, CONN_STATE_NONE, cancellable, &local_err))
  {
    g_propagate_error(err, local_err);
    return FALSE;
  }

  return TRUE;
}

/**
 * mega_http_client_get_response_length:
 * @http_client: a #MegaHttpClient
 * @cancellable: 
 * @err
 *
 * Description...
 *
 * Returns: 
 */
gint64 mega_http_client_get_response_length(MegaHttpClient* http_client, GCancellable* cancellable, GError** err)
{
  GError* local_err = NULL;

  g_return_val_if_fail(MEGA_IS_HTTP_CLIENT(http_client), -1);

  MegaHttpClientPrivate* priv = http_client->priv;

  if (!goto_state(http_client, CONN_STATE_HEADERS_RECEIVED, cancellable, &local_err))
  {
    g_propagate_error(err, local_err);
    return -1;
  }

  if (priv->response_length < 0)
  {
    g_set_error(err, MEGA_HTTP_CLIENT_ERROR, MEGA_HTTP_CLIENT_ERROR_OTHER, "Response length not set");
    return -1;
  }

  return priv->response_length;
}

// {{{ GObject type setup

static void mega_http_client_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaHttpClient *http_client = MEGA_HTTP_CLIENT(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_http_client_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaHttpClient *http_client = MEGA_HTTP_CLIENT(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaHttpClient, mega_http_client, G_TYPE_OBJECT);

static gboolean stri_equal (gconstpointer v1, gconstpointer v2) 
{
  const gchar *string1 = v1;
  const gchar *string2 = v2;

  return g_ascii_strcasecmp (string1, string2) == 0;
}

static guint stri_hash (gconstpointer v)
{
  const signed char *p;
  guint32 h = 5381;

  for (p = v; *p != '\0'; p++)
    h = (h << 5) + h + g_ascii_tolower(*p);

  return h;
}

static void mega_http_client_init(MegaHttpClient *http_client)
{
  MegaHttpClientPrivate* priv = http_client->priv = G_TYPE_INSTANCE_GET_PRIVATE(http_client, MEGA_TYPE_HTTP_CLIENT, MegaHttpClientPrivate);

  priv->client = g_socket_client_new();
  g_socket_client_set_timeout(priv->client, 60);
  priv->request_headers = g_hash_table_new_full(stri_hash, stri_equal, g_free, g_free);
  priv->response_headers = g_hash_table_new_full(stri_hash, stri_equal, g_free, g_free);
  priv->regex_url = g_regex_new("^([a-z]+)://([a-z0-9.-]+(?::([0-9]+))?)(/.+)?$", G_REGEX_CASELESS, 0, NULL);
  priv->regex_status = g_regex_new("^HTTP/([0-9]+\\.[0-9]+) ([0-9]+) (.+)$", 0, 0, NULL);

  // set default headers
  mega_http_client_set_header(http_client, "Referer", "https://mega.co.nz/");
  mega_http_client_set_header(http_client, "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.17 (KHTML, like Gecko) Chrome/24.0.1312.70 Safari/537.17");
  mega_http_client_set_header(http_client, "Connection", "keep-alive");
}

static void mega_http_client_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaHttpClient *http_client = MEGA_HTTP_CLIENT(object);

  // Free everything that may hold reference to MegaHttpClient

  G_OBJECT_CLASS(mega_http_client_parent_class)->dispose(object);
}

static void mega_http_client_finalize(GObject *object)
{
  MegaHttpClient *http_client = MEGA_HTTP_CLIENT(object);
  MegaHttpClientPrivate* priv = http_client->priv;
  
  goto_state(http_client, CONN_STATE_NONE, NULL, NULL);

  g_free(priv->host);
  g_free(priv->resource);
  g_hash_table_destroy(priv->request_headers);
  g_hash_table_destroy(priv->response_headers);
  g_object_unref(priv->client);
  g_regex_unref(priv->regex_url);
  g_regex_unref(priv->regex_status);

  G_OBJECT_CLASS(mega_http_client_parent_class)->finalize(object);
}

static void mega_http_client_class_init(MegaHttpClientClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_http_client_set_property;
  gobject_class->get_property = mega_http_client_get_property;

  gobject_class->dispose = mega_http_client_dispose;
  gobject_class->finalize = mega_http_client_finalize;

  g_type_class_add_private(klass, sizeof(MegaHttpClientPrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
