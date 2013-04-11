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
 * SECTION:mega-aes-ctr-encryptor
 * @short_description: 
 * @see_also: #GObject
 * @stability: Stable
 * @include: mega-aes-ctr-encryptor.h
 *
 * Description...
 */

#include "mega-aes-ctr-encryptor.h"

struct _MegaAesCtrEncryptorPrivate
{
  int dummy;
};

// {{{ GObject property and signal enums

enum MegaAesCtrEncryptorProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaAesCtrEncryptorSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_aes_ctr_encryptor_new:
 *
 * Create new #MegaAesCtrEncryptor object.
 *
 * Returns: #MegaAesCtrEncryptor object.
 */
MegaAesCtrEncryptor* mega_aes_ctr_encryptor_new(void)
{
  MegaAesCtrEncryptor *aes_ctr_encryptor = g_object_new(MEGA_TYPE_AES_CTR_ENCRYPTOR, NULL);

  return aes_ctr_encryptor;
}

static void reset(GConverter *converter)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(converter);
}

static GConverterResult convert(GConverter *converter, const void *inbuf, gsize inbuf_size, void *outbuf, gsize outbuf_size, GConverterFlags flags, gsize *bytes_read, gsize *bytes_written, GError **error)
{
  MegaAesCtrEncryptor *encryptor = MEGA_AES_CTR_ENCRYPTOR(converter);

  // G_CONVERTER_ERROR
  // G_CONVERTER_CONVERTED
  // G_CONVERTER_FINISHED
  // G_CONVERTER_FLUSHED

  // MASK:
  // G_CONVERTER_NO_FLAGS
  // G_CONVERTER_INPUT_AT_END
  // G_CONVERTER_FLUSH 

  return G_CONVERTER_CONVERTED;
}

// {{{ GObject type setup

static void mega_aes_ctr_encryptor_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaAesCtrEncryptor *aes_ctr_encryptor = MEGA_AES_CTR_ENCRYPTOR(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_aes_ctr_encryptor_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaAesCtrEncryptor *aes_ctr_encryptor = MEGA_AES_CTR_ENCRYPTOR(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_aes_ctr_encryptor_converter_iface_init(GConverterIface *iface)
{
  iface->convert = convert;
  iface->reset = reset;
}

G_DEFINE_TYPE_WITH_CODE(MegaAesCtrEncryptor, mega_aes_ctr_encryptor, G_TYPE_OBJECT,
  G_IMPLEMENT_INTERFACE(G_TYPE_CONVERTER, mega_aes_ctr_encryptor_converter_iface_init)
);

static void mega_aes_ctr_encryptor_init(MegaAesCtrEncryptor *aes_ctr_encryptor)
{
  aes_ctr_encryptor->priv = G_TYPE_INSTANCE_GET_PRIVATE(aes_ctr_encryptor, MEGA_TYPE_AES_CTR_ENCRYPTOR, MegaAesCtrEncryptorPrivate);
}

static void mega_aes_ctr_encryptor_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaAesCtrEncryptor *aes_ctr_encryptor = MEGA_AES_CTR_ENCRYPTOR(object);

  // Free everything that may hold reference to MegaAesCtrEncryptor

  G_OBJECT_CLASS(mega_aes_ctr_encryptor_parent_class)->dispose(object);
}

static void mega_aes_ctr_encryptor_finalize(GObject *object)
{
  G_GNUC_UNUSED MegaAesCtrEncryptor *aes_ctr_encryptor = MEGA_AES_CTR_ENCRYPTOR(object);


  G_OBJECT_CLASS(mega_aes_ctr_encryptor_parent_class)->finalize(object);
}

static void mega_aes_ctr_encryptor_class_init(MegaAesCtrEncryptorClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_aes_ctr_encryptor_set_property;
  gobject_class->get_property = mega_aes_ctr_encryptor_get_property;

  gobject_class->dispose = mega_aes_ctr_encryptor_dispose;
  gobject_class->finalize = mega_aes_ctr_encryptor_finalize;

  g_type_class_add_private(klass, sizeof(MegaAesCtrEncryptorPrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
