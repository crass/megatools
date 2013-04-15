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

static mega_session* s;

static GOptionEntry entries[] =
{
  { NULL }
};

int main(int ac, char* av[])
{
  GError *local_err = NULL;

  tool_init(&ac, &av, "- create directories at mega.co.nz", entries);

  if (ac < 2)
  {
    g_printerr("ERROR: No directories specified!\n");
    tool_fini(NULL);
    return 1;
  }

  s = tool_start_session();
  if (!s)
  {
    tool_fini(NULL);
    return 1;
  }

  gint i;
  for (i = 1; i < ac; i++)
  {
    if (!mega_session_mkdir(s, av[i], &local_err))
    {
      g_printerr("ERROR: Can't create directory %s: %s\n", av[i], local_err->message);
      g_clear_error(&local_err);
    }
  }

  mega_session_save(s, NULL);

  tool_fini(s);
  return 0;
}
