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
 * SECTION:mega-http-output-stream
 * @short_description: 
 * @see_also: #GOutputStream
 * @stability: Stable
 * @include: mega-http-output-stream.h
 *
 * Description...
 */

#include "mega-http-output-stream.h"
#include "mega-http-client.h"

struct _MegaHttpOutputStreamPrivate
{
  MegaHttpClient* client;
};

// {{{ GObject property and signal enums

enum MegaHttpOutputStreamProp
{
  PROP_0,
  PROP_CLIENT,
  N_PROPERTIES
};

enum MegaHttpOutputStreamSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_http_output_stream_new:
 *
 * Create new #MegaHttpOutputStream object.
 *
 * Returns: #MegaHttpOutputStream object.
 */
MegaHttpOutputStream* mega_http_output_stream_new(MegaHttpClient* client)
{
  MegaHttpOutputStream *http_output_stream = g_object_new(MEGA_TYPE_HTTP_OUTPUT_STREAM, "client", client, NULL);

  return http_output_stream;
}

static gssize stream_write(GOutputStream *stream, const void *buffer, gsize count, GCancellable *cancellable, GError **error)
{
  MegaHttpOutputStream *http_output_stream = MEGA_HTTP_OUTPUT_STREAM(stream);

  return mega_http_client_write(http_output_stream->priv->client, buffer, count, cancellable, error);
}

// {{{ GObject type setup

static void mega_http_output_stream_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaHttpOutputStream *http_output_stream = MEGA_HTTP_OUTPUT_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      http_output_stream->priv->client = g_value_dup_object(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_http_output_stream_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaHttpOutputStream *http_output_stream = MEGA_HTTP_OUTPUT_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      g_value_set_object(value, http_output_stream->priv->client);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaHttpOutputStream, mega_http_output_stream, G_TYPE_OUTPUT_STREAM);

static void mega_http_output_stream_init(MegaHttpOutputStream *http_output_stream)
{
  http_output_stream->priv = G_TYPE_INSTANCE_GET_PRIVATE(http_output_stream, MEGA_TYPE_HTTP_OUTPUT_STREAM, MegaHttpOutputStreamPrivate);
}

static void mega_http_output_stream_dispose(GObject *object)
{
  //MegaHttpOutputStream *http_output_stream = MEGA_HTTP_OUTPUT_STREAM(object);

  // Free everything that may hold reference to MegaHttpOutputStream

  G_OBJECT_CLASS(mega_http_output_stream_parent_class)->dispose(object);
}

static void mega_http_output_stream_finalize(GObject *object)
{
  MegaHttpOutputStream *http_output_stream = MEGA_HTTP_OUTPUT_STREAM(object);

  if (http_output_stream->priv->client)
    g_object_unref(http_output_stream->priv->client);

  G_OBJECT_CLASS(mega_http_output_stream_parent_class)->finalize(object);
}

static void mega_http_output_stream_class_init(MegaHttpOutputStreamClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_http_output_stream_set_property;
  gobject_class->get_property = mega_http_output_stream_get_property;

  gobject_class->dispose = mega_http_output_stream_dispose;
  gobject_class->finalize = mega_http_output_stream_finalize;

  g_type_class_add_private(klass, sizeof(MegaHttpOutputStreamPrivate));

  G_OUTPUT_STREAM_CLASS(klass)->write_fn = stream_write;

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "client",
    /* nick    */ "Client",
    /* blurb   */ "Set/get client",
    /* is_type */ MEGA_TYPE_HTTP_CLIENT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY
  );

  g_object_class_install_property(gobject_class, PROP_CLIENT, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
