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

static gboolean opt_human;

static GOptionEntry entries[] =
{
  { "human",        'h',   0, G_OPTION_ARG_NONE,    &opt_human,         "Use human readable formatting",  NULL       },
  { NULL }
};

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  mega_session* s;

  tool_init(&ac, &av, "- display mega.co.nz storage quotas/usage", entries);

  s = tool_start_session();
  if (!s)
    return 1;

  mega_user_quota* q = mega_session_user_quota(s, &local_err);
  if (!q)
  {
    g_printerr("ERROR: Can't determine disk usage: %s\n", local_err->message);
    g_clear_error(&local_err);
    goto err;
  }

  if (opt_human)
  {
    g_print("Total: %s\n", g_format_size_full(q->total, G_FORMAT_SIZE_IEC_UNITS));
    g_print("Used:  %s\n", g_format_size_full(q->used, G_FORMAT_SIZE_IEC_UNITS));
    g_print("Free:  %s\n", g_format_size_full(q->total - q->used, G_FORMAT_SIZE_IEC_UNITS));
  }
  else
  {
    g_print("Total: %" G_GUINT64_FORMAT "\n", q->total);
    g_print("Used:  %" G_GUINT64_FORMAT "\n", q->used);
    g_print("Free:  %" G_GUINT64_FORMAT "\n", q->total - q->used);
  }

  g_free(q);

  tool_fini(s);
  return 0;

err:
  tool_fini(s);
  return 1;
}
