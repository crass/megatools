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

#ifndef __MEGA_HTTP_H
#define __MEGA_HTTP_H

#include <glib.h>

#define HTTP_ERROR http_error_quark()

enum 
{
  HTTP_ERROR_NO_RESPONSE,
  HTTP_ERROR_OTHER
};

typedef struct _http http;

typedef gsize (*http_data_fn)(gpointer buf, gsize len, gpointer user_data);
typedef gboolean (*http_progress_fn)(goffset total, goffset now, gpointer user_data);

// functions

http* http_new(void);

void http_set_referer(http* h, const gchar* referer);
void http_set_user_agent(http* h, const gchar* ua);
void http_set_content_type(http* h, const gchar* type);
void http_set_content_length(http* h, goffset len);
void http_no_expect(http* h);
void http_set_header(http* h, const gchar* name, const gchar* value);
void http_set_progress_callback(http* h, http_progress_fn cb, gpointer data);

GString* http_post(http* h, const gchar* url, const gchar* body, gssize body_len, GError** err);
GString* http_post_stream_upload(http* h, const gchar* url, goffset len, http_data_fn read_cb, gpointer user_data, GError** err);
gboolean http_post_stream_download(http* h, const gchar* url, http_data_fn write_cb, gpointer user_data, GError** err);

void http_free(http* h);

GQuark http_error_quark(void);

#endif
