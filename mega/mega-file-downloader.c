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
 * SECTION:mega-file-downloader
 * @title 
 * @short_description: 
 *
 * Description...
 */

#include "mega-file-downloader.h"

struct _MegaFileDownloaderPrivate
{
  int dummy;
};

// {{{ GObject property and signal enums

enum MegaFileDownloaderProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaFileDownloaderSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_file_downloader_new:
 *
 * Create new #MegaFileDownloader object.
 *
 * Returns: #MegaFileDownloader object.
 */
MegaFileDownloader* mega_file_downloader_new(void)
{
  MegaFileDownloader *file_downloader = g_object_new(MEGA_TYPE_FILE_DOWNLOADER, NULL);

  return file_downloader;
}

// {{{ GObject type setup

static void mega_file_downloader_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaFileDownloader *file_downloader = MEGA_FILE_DOWNLOADER(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_file_downloader_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaFileDownloader *file_downloader = MEGA_FILE_DOWNLOADER(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaFileDownloader, mega_file_downloader, G_TYPE_OBJECT);

static void mega_file_downloader_init(MegaFileDownloader *file_downloader)
{
  file_downloader->priv = G_TYPE_INSTANCE_GET_PRIVATE(file_downloader, MEGA_TYPE_FILE_DOWNLOADER, MegaFileDownloaderPrivate);
}

static void mega_file_downloader_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaFileDownloader *file_downloader = MEGA_FILE_DOWNLOADER(object);

  // Free everything that may hold reference to MegaFileDownloader

  G_OBJECT_CLASS(mega_file_downloader_parent_class)->dispose(object);
}

static void mega_file_downloader_finalize(GObject *object)
{
  G_GNUC_UNUSED MegaFileDownloader *file_downloader = MEGA_FILE_DOWNLOADER(object);


  G_OBJECT_CLASS(mega_file_downloader_parent_class)->finalize(object);
}

static void mega_file_downloader_class_init(MegaFileDownloaderClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_file_downloader_set_property;
  gobject_class->get_property = mega_file_downloader_get_property;
  gobject_class->dispose = mega_file_downloader_dispose;
  gobject_class->finalize = mega_file_downloader_finalize;

  g_type_class_add_private(klass, sizeof(MegaFileDownloaderPrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
