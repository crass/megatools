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

#ifndef __MEGA_CHUNKED_CBC_MAC_H__
#define __MEGA_CHUNKED_CBC_MAC_H__

#include <mega/mega-aes-key.h>

#define MEGA_TYPE_CHUNKED_CBC_MAC            (mega_chunked_cbc_mac_get_type())
#define MEGA_CHUNKED_CBC_MAC(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_CHUNKED_CBC_MAC, MegaChunkedCbcMac))
#define MEGA_CHUNKED_CBC_MAC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_CHUNKED_CBC_MAC, MegaChunkedCbcMacClass))
#define MEGA_IS_CHUNKED_CBC_MAC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_CHUNKED_CBC_MAC))
#define MEGA_IS_CHUNKED_CBC_MAC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_CHUNKED_CBC_MAC))
#define MEGA_CHUNKED_CBC_MAC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_CHUNKED_CBC_MAC, MegaChunkedCbcMacClass))

typedef struct _MegaChunkedCbcMac MegaChunkedCbcMac;
typedef struct _MegaChunkedCbcMacClass MegaChunkedCbcMacClass;
typedef struct _MegaChunkedCbcMacPrivate MegaChunkedCbcMacPrivate;

struct _MegaChunkedCbcMac
{
  GObject parent;
  MegaChunkedCbcMacPrivate* priv;
};

struct _MegaChunkedCbcMacClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_chunked_cbc_mac_get_type   (void) G_GNUC_CONST;

MegaChunkedCbcMac*      mega_chunked_cbc_mac_new        (void);

void                    mega_chunked_cbc_mac_setup      (MegaChunkedCbcMac* mac, MegaAesKey* key, guchar* iv);
void                    mega_chunked_cbc_mac_update     (MegaChunkedCbcMac* mac, const guchar* data, gsize len);
void                    mega_chunked_cbc_mac_finish     (MegaChunkedCbcMac* mac, guchar* meta_mac);

G_END_DECLS

#endif
