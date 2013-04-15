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

static gchar* opt_path = ".";
static gboolean opt_stream = FALSE;
static gboolean opt_noprogress = FALSE;

static GOptionEntry entries[] =
{
  { "path",          '\0',   0, G_OPTION_ARG_STRING,  &opt_path,  "Local directory or file name, to save data to",  "PATH" },
  { "no-progress",   '\0',   0, G_OPTION_ARG_NONE,    &opt_noprogress,  "Disable progress bar",   NULL},
  { NULL }
};

static gchar* cur_file = NULL;

static gboolean status_callback(mega_status_data* data, gpointer userdata)
{
  if (opt_stream && data->type == MEGA_STATUS_DATA)
  {
    fwrite(data->data.buf, data->data.size, 1, stdout);
    fflush(stdout);
  }

  if (data->type == MEGA_STATUS_FILEINFO)
  {
    cur_file = g_strdup(data->fileinfo.name);
  }

  if (!opt_noprogress && data->type == MEGA_STATUS_PROGRESS)
  {
    gchar* done_str = g_format_size_full(data->progress.done, G_FORMAT_SIZE_IEC_UNITS);
    gchar* total_str = g_format_size_full(data->progress.total, G_FORMAT_SIZE_IEC_UNITS);

    if (data->progress.total > 0)
      g_print(ESC_WHITE "%s" ESC_NORMAL ": " ESC_GREEN "%" G_GINT64_FORMAT  "%%" ESC_NORMAL " - " ESC_GREEN "%s" ESC_NORMAL " of %s" ESC_CLREOL "\r", cur_file, 100 * data->progress.done / data->progress.total, done_str, total_str);

    g_free(done_str);
    g_free(total_str);
  }

  return FALSE;
}

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  mega_session* s;

  tool_init(&ac, &av, "- download individual files from mega.co.nz", entries);

  if (!strcmp(opt_path, "-"))
    opt_noprogress = opt_stream = TRUE;

  if (ac < 2)
  {
    g_printerr("ERROR: No files specified for download!\n");
    tool_fini(NULL);
    return 1;
  }

  if (opt_stream && ac != 2)
  {
    g_printerr("ERROR: Can't stream from multiple files!\n");
    tool_fini(NULL);
    return 1;
  }

  s = tool_start_session();
  if (!s)
  {
    tool_fini(NULL);
    return 1;
  }

  mega_session_watch_status(s, status_callback, NULL);

  gint i;
  for (i = 1; i < ac; i++)
  {
    // perform download
    if (!mega_session_get(s, opt_stream ? NULL : opt_path, av[i], &local_err))
    {
      if (!opt_noprogress)
        g_print("\r" ESC_CLREOL "\n");
      g_printerr("ERROR: Download failed for '%s': %s\n", av[i], local_err->message);
      g_clear_error(&local_err);
    }
    else
    {
      if (!opt_noprogress)
        g_print("\r" ESC_CLREOL "Downloaded %s\n", cur_file);
    }
  }

  tool_fini(s);
  return 0;
}
