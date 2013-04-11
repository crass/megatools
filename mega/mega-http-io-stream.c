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
 * SECTION:mega-http-io-stream
 * @short_description: 
 * @see_also: #GIOStream
 * @stability: Stable
 * @include: mega-http-io-stream.h
 *
 * Description...
 */

#include "mega-http-io-stream.h"
#include "mega-http-input-stream.h"
#include "mega-http-output-stream.h"
#include "mega-http-client.h"

struct _MegaHttpIOStreamPrivate
{
  MegaHttpClient* client;
};

// {{{ GObject property and signal enums

enum MegaHttpIOStreamProp
{
  PROP_0,
  PROP_CLIENT,
  N_PROPERTIES
};

enum MegaHttpIOStreamSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_http_io_stream_new:
 *
 * Create new #MegaHttpIOStream object.
 *
 * Returns: #MegaHttpIOStream object.
 */
MegaHttpIOStream* mega_http_io_stream_new(MegaHttpClient* client)
{
  MegaHttpIOStream *http_io_stream = g_object_new(MEGA_TYPE_HTTP_IO_STREAM, "client", client, NULL);

  return http_io_stream;
}

static GInputStream* get_input_stream(GIOStream* stream)
{
  MegaHttpIOStream* http_io_stream = MEGA_HTTP_IO_STREAM(stream);

  return G_INPUT_STREAM(mega_http_input_stream_new(http_io_stream->priv->client));
}

static GOutputStream* get_output_stream(GIOStream* stream)
{
  MegaHttpIOStream* http_io_stream = MEGA_HTTP_IO_STREAM(stream);

  return G_OUTPUT_STREAM(mega_http_output_stream_new(http_io_stream->priv->client));
}

static gboolean close_fn(GIOStream* stream, GCancellable* cancellable, GError** error)
{
  MegaHttpIOStream* http_io_stream = MEGA_HTTP_IO_STREAM(stream);

  return mega_http_client_close(http_io_stream->priv->client, FALSE, cancellable, error);
}

// {{{ GObject type setup

static void mega_http_io_stream_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaHttpIOStream *http_io_stream = MEGA_HTTP_IO_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      http_io_stream->priv->client = g_value_dup_object(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_http_io_stream_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaHttpIOStream *http_io_stream = MEGA_HTTP_IO_STREAM(object);

  switch (property_id)
  {
    case PROP_CLIENT:
      g_value_set_object(value, http_io_stream->priv->client);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaHttpIOStream, mega_http_io_stream, G_TYPE_IO_STREAM);

static void mega_http_io_stream_init(MegaHttpIOStream *http_io_stream)
{
  http_io_stream->priv = G_TYPE_INSTANCE_GET_PRIVATE(http_io_stream, MEGA_TYPE_HTTP_IO_STREAM, MegaHttpIOStreamPrivate);
}

static void mega_http_io_stream_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaHttpIOStream *http_io_stream = MEGA_HTTP_IO_STREAM(object);

  // Free everything that may hold reference to MegaHttpIOStream

  G_OBJECT_CLASS(mega_http_io_stream_parent_class)->dispose(object);
}

static void mega_http_io_stream_finalize(GObject *object)
{
  MegaHttpIOStream *http_io_stream = MEGA_HTTP_IO_STREAM(object);

  if (http_io_stream->priv->client)
    g_object_unref(http_io_stream->priv->client);

  G_OBJECT_CLASS(mega_http_io_stream_parent_class)->finalize(object);
}

static void mega_http_io_stream_class_init(MegaHttpIOStreamClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_http_io_stream_set_property;
  gobject_class->get_property = mega_http_io_stream_get_property;

  gobject_class->dispose = mega_http_io_stream_dispose;
  gobject_class->finalize = mega_http_io_stream_finalize;

  g_type_class_add_private(klass, sizeof(MegaHttpIOStreamPrivate));

  GIOStreamClass* giostream_class = G_IO_STREAM_CLASS(klass);
  giostream_class->get_input_stream = get_input_stream;
  giostream_class->get_output_stream = get_output_stream;
  giostream_class->close_fn = close_fn;

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "client",
    /* nick    */ "Client",
    /* blurb   */ "Set/get client",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY
  );

  g_object_class_install_property(gobject_class, PROP_CLIENT, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
