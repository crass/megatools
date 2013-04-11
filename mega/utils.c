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

#include "utils.h"
#include <string.h>

/**
 * mega_base64urlencode:
 * @data: (element-type guchar) (array length=len) (transfer none):
 * @len:
 *
 * Returns: (transfer full):
 */
gchar* mega_base64urlencode(const guchar* data, gsize len)
{
  gint i, shl;
  gchar *sh, *she, *p;

  g_return_val_if_fail(data != NULL, NULL);
  g_return_val_if_fail(len > 0, NULL);

  sh = g_base64_encode(data, len);
  shl = strlen(sh);

  she = g_malloc0(shl + 1), p = she;
  for (i = 0; i < shl; i++)
  {
    if (sh[i] == '+')
      *p = '-';
    else if (sh[i] == '/')
      *p = '_';
    else if (sh[i] == '=')
      continue;
    else
      *p = sh[i];
    p++;
  }

  *p = '\0';

  g_free(sh);
  return she;
}

/**
 * mega_base64urldecode:
 * @str:
 * @len: (out):
 *
 * Returns: (transfer full) (element-type guchar) (array length=len):
 */
guchar* mega_base64urldecode(const gchar* str, gsize* len)
{
  GString* s;
  gint i;

  g_return_val_if_fail(str != NULL, NULL);
  g_return_val_if_fail(len != NULL, NULL);

  s = g_string_new(str);

  for (i = 0; i < s->len; i++)
  {
    if (s->str[i] == '-')
      s->str[i] = '+';
    else if (s->str[i] == '_')
      s->str[i] = '/';
  }

  gint eqs = (s->len * 3) & 0x03;
  for (i = 0; i < eqs; i++)
    g_string_append_c(s, '=');

  guchar* data = g_base64_decode(s->str, len);

  g_string_free(s, TRUE);

  return data;
}

/**
 * mega_format_hex:
 * @data: (element-type guchar) (array length=len) (transfer none):
 * @len:
 */
gchar* mega_format_hex(const guchar* data, gsize len, MegaHexFormat fmt)
{
  gsize i;
  GString* str;

  g_return_val_if_fail(data != NULL, NULL);
  
  str = g_string_sized_new(64);
  
  if (fmt == MEGA_HEX_FORMAT_PACKED)
  {
    for (i = 0; i < len; i++)
      g_string_append_printf(str, "%02X", (guint)data[i]);
  }
  else if (fmt == MEGA_HEX_FORMAT_C)
  {
    for (i = 0; i < len; i++)
      g_string_append_printf(str, "%s0x%02X", i ? " " : "", (guint)data[i]);
  }
  else if (fmt == MEGA_HEX_FORMAT_STRING)
  {
    g_string_append(str, "\"");
    for (i = 0; i < len; i++)
      g_string_append_printf(str, "\\x%02X", (guint)data[i]);
    g_string_append(str, "\"");
  }
    
  return g_string_free(str, FALSE);
}

/**
 * mega_gbytes_to_string:
 * @bytes: (transfer none):
 * @len: (out):
 *
 * Returns: (transfer full) (element-type guint8) (array length=len): Data
 */
guchar* mega_gbytes_to_string(GBytes *bytes, gsize *len)
{
  g_return_val_if_fail(bytes != NULL, NULL);
  g_return_val_if_fail(len != NULL, NULL);

  gchar* str = g_malloc0(g_bytes_get_size(bytes) + 1);
  memcpy(str, g_bytes_get_data(bytes, NULL), g_bytes_get_size(bytes));
  if (len)
    *len = g_bytes_get_size(bytes);
  return str;
}

//Send this urlencoded when uploading chunk: '?c=' + mega_base64urlencode(chksum(ul_sendchunks[p].buffer))

void mega_checksum(const guchar* buffer, gsize len, guchar csum[12])
{
  memset(csum, 0, 12);

  while (len--)
    csum[len % 12] ^= buffer[len];
}
