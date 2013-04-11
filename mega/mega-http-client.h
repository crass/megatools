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

#ifndef __MEGA_HTTP_CLIENT_H__
#define __MEGA_HTTP_CLIENT_H__

#include <mega/megatypes.h>

#define MEGA_TYPE_HTTP_CLIENT            (mega_http_client_get_type())
#define MEGA_HTTP_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_HTTP_CLIENT, MegaHttpClient))
#define MEGA_HTTP_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_HTTP_CLIENT, MegaHttpClientClass))
#define MEGA_IS_HTTP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_HTTP_CLIENT))
#define MEGA_IS_HTTP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_HTTP_CLIENT))
#define MEGA_HTTP_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_HTTP_CLIENT, MegaHttpClientClass))

typedef struct _MegaHttpClient MegaHttpClient;
typedef struct _MegaHttpClientClass MegaHttpClientClass;
typedef struct _MegaHttpClientPrivate MegaHttpClientPrivate;

struct _MegaHttpClient
{
  GObject parent;
  MegaHttpClientPrivate* priv;
};

struct _MegaHttpClientClass
{
  GObjectClass parent_class;
};

#define MEGA_HTTP_CLIENT_ERROR mega_http_client_error_quark()

typedef enum 
{
  MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN,
  MEGA_HTTP_CLIENT_ERROR_OTHER
} MegaHttpClientError;

G_BEGIN_DECLS

GQuark                  mega_http_client_error_quark           (void);
GType                   mega_http_client_get_type              (void) G_GNUC_CONST;
                                                               
MegaHttpClient*         mega_http_client_new                   (void);
void                    mega_http_client_set_content_type      (MegaHttpClient* http_client, const gchar* content_type);
void                    mega_http_client_set_content_length    (MegaHttpClient* http_client, guint64 content_length);
void                    mega_http_client_set_header            (MegaHttpClient* http_client, const gchar* name, const gchar* value);

MegaHttpIOStream*       mega_http_client_post                  (MegaHttpClient* http_client, const gchar* url, gint64 request_length, GError** err);
GString*                mega_http_client_post_simple           (MegaHttpClient* http_client, const gchar* url, const gchar* body, gssize body_len, GError** err);

// semi internal, use iostream instead
gssize                  mega_http_client_read                  (MegaHttpClient* http_client, guchar* buffer, gsize count, GCancellable* cancellable, GError** err);
gssize                  mega_http_client_write                 (MegaHttpClient* http_client, const guchar* buffer, gsize count, GCancellable* cancellable, GError** err);
gboolean                mega_http_client_close                 (MegaHttpClient* http_client, gboolean force, GCancellable* cancellable, GError** err);
gint64                  mega_http_client_get_response_length   (MegaHttpClient* http_client, GCancellable* cancellable, GError** err);

G_END_DECLS

/*
 * HTTP Client
 * -----------
 *
 * Minimalistic streaming http client implementing persistent connections using
 * HTTP 1.1. It integrates well into GIO.
 *
 * Features:
 *
 * - Perform Seekable POST to a specific URL
 *   - Seekable POSTs work by appending '/start-end' to POSTs URL, and then
 *   issuing a request and reading from the the response
 *   
 * - Perform Normal POST to a specific URL
 *
 *
 */

#endif
