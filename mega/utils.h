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

#ifndef __MEGA_PRIV_UTILS_H__
#define __MEGA_PRIV_UTILS_H__

#include <glib.h>

typedef enum 
{
  MEGA_HEX_FORMAT_PACKED = 0,
  MEGA_HEX_FORMAT_C,
  MEGA_HEX_FORMAT_STRING
} MegaHexFormat;

G_BEGIN_DECLS

gchar* mega_base64urlencode(const guchar* data, gsize len);
guchar* mega_base64urldecode(const gchar* str, gsize* len);

guchar* mega_gbytes_to_string(GBytes *bytes, gsize *len);

gchar* mega_format_hex(const guchar* data, gsize len, MegaHexFormat fmt);

G_END_DECLS

#endif
