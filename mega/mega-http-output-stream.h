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

#ifndef __MEGA_HTTP_OUTPUT_STREAM_H__
#define __MEGA_HTTP_OUTPUT_STREAM_H__

#include <mega/megatypes.h>

#define MEGA_TYPE_HTTP_OUTPUT_STREAM            (mega_http_output_stream_get_type())
#define MEGA_HTTP_OUTPUT_STREAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_HTTP_OUTPUT_STREAM, MegaHttpOutputStream))
#define MEGA_HTTP_OUTPUT_STREAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_HTTP_OUTPUT_STREAM, MegaHttpOutputStreamClass))
#define MEGA_IS_HTTP_OUTPUT_STREAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_HTTP_OUTPUT_STREAM))
#define MEGA_IS_HTTP_OUTPUT_STREAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_HTTP_OUTPUT_STREAM))
#define MEGA_HTTP_OUTPUT_STREAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_HTTP_OUTPUT_STREAM, MegaHttpOutputStreamClass))

typedef struct _MegaHttpOutputStreamClass MegaHttpOutputStreamClass;
typedef struct _MegaHttpOutputStreamPrivate MegaHttpOutputStreamPrivate;

struct _MegaHttpOutputStream
{
  GOutputStream parent;
  MegaHttpOutputStreamPrivate* priv;
};

struct _MegaHttpOutputStreamClass
{
  GOutputStreamClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_http_output_stream_get_type(void) G_GNUC_CONST;

MegaHttpOutputStream*   mega_http_output_stream_new     (MegaHttpClient* client);

G_END_DECLS

#endif
