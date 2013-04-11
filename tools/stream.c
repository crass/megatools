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

#include "tools.h"

static gboolean status_callback(mega_status_data* data, gpointer userdata)
{
  if (data->type == MEGA_STATUS_DATA)
  {
    fwrite(data->data.buf, data->data.size, 1, stdout);
    fflush(stdout);
  }

  return FALSE;
}

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  mega_session* s;
  GMatchInfo* m = NULL;
  GRegex* r;
  gint i;

  tool_init(&ac, &av, "stream files from mega.co.nz", NULL);

  s = tool_start_session();
  if (!s)
    return 1;

  mega_session_watch_status(s, status_callback, NULL);

  // create mega download link parser regex
  r = g_regex_new("^https?://mega.co.nz/#!([a-z0-9_-]{8})!([a-z0-9_-]{43})$", G_REGEX_CASELESS, 0, NULL);
  g_assert(r != NULL);

  // process links
  for (i = 1; i < ac; i++)
  {
    if (!g_regex_match(r, av[i], 0, &m))
    {
      if (!mega_session_get(s, NULL, av[i], &local_err))
      {
        g_printerr("ERROR: Download failed for '%s': %s\n", av[i], local_err->message);
        g_clear_error(&local_err);
      }
    }
    else
    {
      gchar* handle = g_match_info_fetch(m, 1);
      gchar* key = g_match_info_fetch(m, 2);
      g_match_info_unref(m);

      if (!mega_session_dl(s, handle, key, NULL, &local_err))
      {
        g_printerr("ERROR: Download failed for '%s': %s\n", av[i], local_err->message);
        g_clear_error(&local_err);
      }

      g_free(handle);
      g_free(key);
    }
  }

  tool_fini(s);
  return 0;
}
