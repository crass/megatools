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

static GOptionEntry entries[] =
{
  { "path",          'p',   0, G_OPTION_ARG_STRING,  &opt_path,  "Local directory or file name, to save data to",  "PATH" },
  { NULL }
};

static gchar* cur_file = NULL;
static mega_session* s;

static gboolean status_callback(mega_status_data* data, gpointer userdata)
{
  if (data->type == MEGA_STATUS_FILEINFO)
  {
    cur_file = g_strdup(data->fileinfo.name);
  }

  if (data->type == MEGA_STATUS_PROGRESS)
  {
    gchar* done_str = g_format_size_full(data->progress.done, G_FORMAT_SIZE_IEC_UNITS);
    gchar* total_str = g_format_size_full(data->progress.total, G_FORMAT_SIZE_IEC_UNITS);

    if (data->progress.total > 0)
      g_print(ESC_WHITE "%s" ESC_NORMAL ": " ESC_GREEN "%" G_GUINT64_FORMAT "%%" ESC_NORMAL " - " ESC_GREEN "%s" ESC_NORMAL " of %s" ESC_CLREOL "\r", cur_file, 100 * data->progress.done / data->progress.total, done_str, total_str);

    g_free(done_str);
    g_free(total_str);
  }

  return FALSE;
}

// download operation

static gboolean dl_sync_file(mega_node* node, GFile* file, const gchar* remote_path)
{
  GError *local_err = NULL;
  gchar* local_path = g_file_get_path(file);

  if (g_file_query_exists(file, NULL))
  {
    g_printerr("ERROR: File already exists at %s\n", local_path);
    return FALSE;
  }

  g_print("F %s\n", local_path);

  if (!mega_session_get(s, g_file_get_path(file), remote_path, &local_err))
  {
    g_print("\r" ESC_CLREOL);
    g_printerr("ERROR: Download failed for %s: %s\n", remote_path, local_err->message);
    g_clear_error(&local_err);
    return FALSE;
  }

  g_print("\r" ESC_CLREOL);

  return TRUE;
}

static gboolean dl_sync_dir(mega_node* node, GFile* file, const gchar* remote_path)
{
  GError *local_err = NULL;
  gchar* local_path = g_file_get_path(file);

  if (!g_file_query_exists(file, NULL))
  {
    g_print("D %s\n", local_path);

    if (!g_file_make_directory(file, NULL, &local_err))
    {
      g_printerr("ERROR: Can't create local directory %s: %s\n", local_path, local_err->message);
      g_clear_error(&local_err);
      return FALSE;
    }
  }
  else
  {
    if (g_file_query_file_type(file, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL) != G_FILE_TYPE_DIRECTORY)
    {
      g_printerr("ERROR: Can't create local directory %s: file exists\n", local_path);
      return FALSE;
    }
  }

  // sync children
  GSList* children = mega_session_get_node_chilren(s, node), *i;
  for (i = children; i; i = i->next)
  {
    mega_node* child = i->data;
    gchar* child_remote_path = g_strconcat(remote_path, "/", child->name, NULL);
    GFile* child_file = g_file_get_child(file, child->name);

    if (child->type == 0)
    {
      dl_sync_file(child, child_file, child_remote_path);
    }
    else
    {
      dl_sync_dir(child, child_file, child_remote_path);
    }

    g_object_unref(child_file);
    g_free(child_remote_path);
  }

  g_slist_free(children);
  return TRUE;
}

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  GRegex *file_regex, *folder_regex;
  gchar* key;
  gchar* handle;
  gint i;

  tool_init_bare(&ac, &av, "- download exported files from mega.co.nz", entries);

  // prepare link parsers

  file_regex = g_regex_new("^https?://mega.co.nz/#!([a-z0-9_-]{8})!([a-z0-9_-]{43})$", G_REGEX_CASELESS, 0, NULL);
  g_assert(file_regex != NULL);

  folder_regex = g_regex_new("^https?://mega.co.nz/#F!([a-z0-9_-]{8})!([a-z0-9_-]{22})$", G_REGEX_CASELESS, 0, NULL);
  g_assert(folder_regex != NULL);

  // create session

  s = mega_session_new();

  mega_session_watch_status(s, status_callback, NULL);

  // process links
  for (i = 1; i < ac; i++)
  {
    GMatchInfo* m1 = NULL;
    GMatchInfo* m2 = NULL;
    key = NULL;
    handle = NULL;

    if (g_regex_match(file_regex, av[i], 0, &m1))
    {
      handle = g_match_info_fetch(m1, 1);
      key = g_match_info_fetch(m1, 2);

      // perform download
      if (!mega_session_dl(s, handle, key, opt_path, &local_err))
      {
        g_print("\r" ESC_CLREOL "\n");
        g_printerr("ERROR: Download failed for '%s': %s\n", av[i], local_err->message);
        g_clear_error(&local_err);
      }
      else
      {
        g_print("\r" ESC_CLREOL "Downloaded %s\n", cur_file);
      }
    }
    else if (g_regex_match(folder_regex, av[i], 0, &m2))
    {
      handle = g_match_info_fetch(m2, 1);
      key = g_match_info_fetch(m2, 2);

      // perform download
      if (!mega_session_open_exp_folder(s, handle, key, &local_err))
      {
        g_printerr("ERROR: Can't open folder '%s': %s\n", av[i], local_err->message);
        g_clear_error(&local_err);
      }
      else
      {
        GSList* l = mega_session_ls(s, "/", FALSE);
        if (g_slist_length(l) == 1)
        {
          mega_node* root_node = l->data;

          GFile* local_dir = g_file_new_for_path(opt_path);
          if (g_file_query_file_type(local_dir, G_FILE_QUERY_INFO_NOFOLLOW_SYMLINKS, NULL) == G_FILE_TYPE_DIRECTORY)
          {
            dl_sync_dir(root_node, local_dir, root_node->path);
          }
          else
          {
            g_printerr("ERROR: %s must be a directory\n", opt_path);
          }
        }
        else
        {
          g_printerr("ERROR: EXP folder fs has multiple toplevel nodes? Weird!\n");
        }
      }
    }
    else
    {
      g_printerr("ERROR: Skipping invalid Mega download link: %s\n", av[i]);
    }

    if (m1)
      g_match_info_unref(m1);
    if (m2)
      g_match_info_unref(m2);
    g_free(handle);
    g_free(key);
  }

  tool_fini(s);
  return 0;
}
