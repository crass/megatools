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

#ifndef __MEGA_FILE_UPLOADER_H__
#define __MEGA_FILE_UPLOADER_H__

#include <glib-object.h>

#define MEGA_TYPE_FILE_UPLOADER            (mega_file_uploader_get_type())
#define MEGA_FILE_UPLOADER(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_FILE_UPLOADER, MegaFileUploader))
#define MEGA_FILE_UPLOADER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_FILE_UPLOADER, MegaFileUploaderClass))
#define MEGA_IS_FILE_UPLOADER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_FILE_UPLOADER))
#define MEGA_IS_FILE_UPLOADER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_FILE_UPLOADER))
#define MEGA_FILE_UPLOADER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_FILE_UPLOADER, MegaFileUploaderClass))

typedef struct _MegaFileUploader MegaFileUploader;
typedef struct _MegaFileUploaderClass MegaFileUploaderClass;
typedef struct _MegaFileUploaderPrivate MegaFileUploaderPrivate;

struct _MegaFileUploader
{
  GObject parent;
  MegaFileUploaderPrivate* priv;
};

struct _MegaFileUploaderClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_file_uploader_get_type     (void) G_GNUC_CONST;

MegaFileUploader*       mega_file_uploader_new          (void);

G_END_DECLS

#endif
