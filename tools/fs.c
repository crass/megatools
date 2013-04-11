#define FUSE_USE_VERSION 26
#include <fuse.h>
#include <errno.h>
#include "tools.h"

static mega_session* s;

// {{{ Read file/dir attributes

static int mega_getattr(const char *path, struct stat *stbuf)
{
  memset(stbuf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) 
  {
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 1;
    return 0;
  } 
  else
  {
    mega_node* n = mega_session_stat(s, path);

    if (n)
    {
      stbuf->st_mode = n->type == MEGA_NODE_FILE ? S_IFREG | 0644 : S_IFDIR | 0755;
      stbuf->st_nlink = 1;
      stbuf->st_size = n->size;
      stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = n->timestamp;
      return 0;
    }
  } 

  return -ENOENT;
}

static int mega_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  GSList* l = mega_session_ls(s, path, FALSE), *i;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  for (i = l; i; i = i->next)
  {
    struct stat st;
    mega_node* n = i->data;

    memset(&st, 0, sizeof(st));
    st.st_mode = n->type == MEGA_NODE_FILE ? S_IFREG | 0644 : S_IFDIR | 0755;
    st.st_nlink = 1;
    st.st_size = n->size;
    st.st_atime = st.st_mtime = st.st_ctime = n->timestamp;

    if (filler(buf, n->name, &st, 0))
      break;
  }

  g_slist_free(l);
  return 0;
}

// }}}
// {{{ Create/remove directories

static int mega_mkdir(const char *path, mode_t mode)
{
  GError *local_err = NULL;

  if (!mega_session_mkdir(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

static int mega_rmdir(const char *path)
{
  GError *local_err = NULL;

  if (!mega_session_rm(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

// }}}
// {{{ Create/read symlinks

static int mega_symlink(const char *from, const char *to)
{
  return -ENOTSUP;
}

static int mega_readlink(const char *path, char *buf, size_t size)
{
  return -ENOTSUP;
}

static int mega_link(const char *from, const char *to)
{
  return -ENOTSUP;
}

// }}}
// {{{ Remove files

static int mega_unlink(const char *path)
{
  GError *local_err = NULL;

  if (!mega_session_rm(s, path, &local_err))
  {
    g_clear_error(&local_err);
    return -ENOENT;
  }

  return 0;
}

// }}}
// {{{ Rename files

static int mega_rename(const char *from, const char *to)
{
  return -ENOTSUP;
}

// }}}
// {{{ File access operations

static int mega_truncate(const char *path, off_t size)
{
  return -ENOTSUP;
}

static int mega_open(const char *path, struct fuse_file_info *fi)
{
  return -ENOTSUP;
}

static int mega_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  return -ENOTSUP;
}

static int mega_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  return -ENOTSUP;
}

static int mega_release(const char *path, struct fuse_file_info *fi)
{
  return 0;
}

// }}}
// {{{ Ops structure

static struct fuse_operations mega_oper = {
	.getattr	= mega_getattr,
	.readlink	= mega_readlink,
	.readdir	= mega_readdir,
	.mkdir		= mega_mkdir,
	.link		= mega_link,
	.symlink	= mega_symlink,
	.unlink		= mega_unlink,
	.rmdir		= mega_rmdir,
	.rename		= mega_rename,
	.truncate	= mega_truncate,
	.open		= mega_open,
	.read		= mega_read,
	.write		= mega_write,
	.release	= mega_release,
};

// }}}
// {{{ main()

int main(int ac, char* av[])
{
  GError *local_err = NULL;

  tool_allow_unknown_options = TRUE;
  tool_init(&ac, &av, "mount_directory - mount files stored at mega.co.nz", NULL);

  s = tool_start_session();
  if (!s)
    return 1;

  int rs = fuse_main(ac, av, &mega_oper, NULL);

  tool_fini(s);
  return rs;
}

// }}}
