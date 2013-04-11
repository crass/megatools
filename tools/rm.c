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

static GOptionEntry entries[] =
{
  { NULL }
};

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  static mega_session* s;

  tool_init(&ac, &av, "- remove files from mega.co.nz", entries);

  s = tool_start_session();
  if (!s)
    return 1;

  gint i;
  for (i = 1; i < ac; i++)
  {
    if (!mega_session_rm(s, av[i], &local_err))
    {
      g_printerr("ERROR: Can't remove %s: %s\n", av[i], local_err->message);
      g_clear_error(&local_err);
    }
  }

  mega_session_save(s, NULL);

  tool_fini(s);
  return 0;
}
