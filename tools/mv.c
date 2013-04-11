#include "tools.h"

static gboolean opt_force;

static GOptionEntry entries[] =
{
  //{ "force",          'f',   0, G_OPTION_ARG_NONE,    &opt_force,         "Overwrite files",                   NULL },
  { NULL }
};

int main(int ac, char* av[])
{
  GError *local_err = NULL;
  mega_session* s;

  tool_init(&ac, &av, "- move files on the remote filesystem at mega.co.nz", entries);

  if (ac < 3)
  {
    g_printerr("ERROR: You must specify both source path(s) and destination path\nExample: megamv /Root/test.mp3 /Root/Subdir/");
    return 1;
  }

  s = tool_start_session();
  if (!s)
    return 1;

  gboolean rename = FALSE;

  // check destination path
  mega_node* destination = mega_session_stat(s, av[ac - 1]);
  if (destination)
  {
    if (destination->type == MEGA_NODE_FILE)
    {
      g_printerr("Destination file already exists: %s", destination->path);
      goto err;
    }

    if (!mega_node_is_writable(s, destination) || destination->type == MEGA_NODE_NETWORK || destination->type == MEGA_NODE_CONTACT)
    {
      g_printerr("You can't move files into: %s", destination->path);
      goto err;
    }
  }
  else
  {
    rename = TRUE;

    gchar* parent_path = g_path_get_dirname(av[ac - 1]);
    destination = mega_session_stat(s, parent_path);
    g_free(parent_path);

    if (!destination)
    {
      g_printerr("Destination directory doesn't exist: %s", parent_path);
      goto err;
    }

    if (destination->type == MEGA_NODE_FILE)
    {
      g_printerr("Destination is not directory: %s", destination->path);
      goto err;
    }

    if (!mega_node_is_writable(s, destination) || destination->type == MEGA_NODE_NETWORK || destination->type == MEGA_NODE_CONTACT)
    {
      g_printerr("You can't move files into: %s", destination->path);
      goto err;
    }
  }

  if (rename && ac > 3)
  {
    g_printerr("You can't use multiple source paths when renaming file or directory");
    goto err;
  }

  // enumerate source paths
  gint i;
  for (i = 1; i < ac - 1; i++)
  {
    mega_node* n = mega_session_stat(s, av[i]);

    if (!n)
    {
      g_printerr("Source file doesn't exists: %s", av[i]);
      goto err;
    }

    if (n->type != MEGA_NODE_FILE && n->type != MEGA_NODE_FOLDER)
    {
      g_printerr("Source is not movable: %s", av[i]);
      goto err;
    }

    // check destination
    gchar* basename = g_path_get_basename(n->path);
    gchar* tmp = g_strconcat(destination->path, "/", basename, NULL);
    g_free(basename);

    // check destination path
    mega_node* dn = mega_session_stat(s, tmp);
    if (dn)
    {
      g_printerr("Destination file already exists: %s", dn->path);
      g_free(tmp);
      goto err;
    }


    // perform move
    //if (!mega_session_mkdir(s, av[i], &local_err))
    //{
      //g_printerr("ERROR: Can't create directory %s: %s\n", av[i], local_err->message);
      //g_clear_error(&local_err);
    //}
    g_print("mv %s %s/%s\n", n->path, destination->path, tmp);

    g_free(tmp);
  }

  mega_session_save(s, NULL);

  tool_fini(s);
  return 0;

err:
  tool_fini(s);
  return 1;
}
