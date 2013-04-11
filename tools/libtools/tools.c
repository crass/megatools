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

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <locale.h>

#include "config.h"
#include "tools.h"

#ifdef G_OS_WIN32
#include <windows.h>
#else
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#endif

#ifdef G_OS_WIN32
#define MEGA_RC_FILENAME "mega.ini"
#else
#define MEGA_RC_FILENAME ".megarc"
#endif

static GOptionContext* opt_context;
static gchar* opt_username;
static gchar* opt_password;
static gchar* opt_config;
static gboolean opt_reload_files;
static gint opt_cache_timout = 10 * 60;
static gboolean opt_version;
static gboolean opt_no_config;
static gboolean opt_no_ask_password;
gboolean tool_allow_unknown_options = FALSE;

static GOptionEntry basic_options[] =
{
  { "version",            '\0',  0, G_OPTION_ARG_NONE,    &opt_version,      "Show version information",           NULL    },
  { NULL }
};

static GOptionEntry auth_options[] =
{
  { "username",            'u',  0, G_OPTION_ARG_STRING,  &opt_username,        "Account username (email)",               "USERNAME" },
  { "password",            'p',  0, G_OPTION_ARG_STRING,  &opt_password,        "Account password",                       "PASSWORD" },
  { "config",             '\0',  0, G_OPTION_ARG_STRING,  &opt_config,          "Load configuration from a file",         "PATH"     },
  { "ignore-config-file", '\0',  0, G_OPTION_ARG_NONE,    &opt_no_config,       "Disable loading " MEGA_RC_FILENAME,      NULL       },
  { "no-ask-password",    '\0',  0, G_OPTION_ARG_NONE,    &opt_no_ask_password, "Never ask interactively for a password", NULL       },
  { "reload",             '\0',  0, G_OPTION_ARG_NONE,    &opt_reload_files,    "Reload filesystem cache",                NULL       },
  { NULL }
};

#if GLIB_CHECK_VERSION(2, 32, 0)

static GMutex* openssl_mutexes = NULL;

static void openssl_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    g_mutex_lock(openssl_mutexes + type);
  else
    g_mutex_unlock(openssl_mutexes + type);
}

static unsigned long openssl_thread_id_callback()
{
  unsigned long ret;
  ret = (unsigned long)g_thread_self();
  return ret;
}

static void init_openssl_locking()
{
  gint i;

  // initialize OpenSSL locking for multi-threaded operation
  openssl_mutexes = g_new(GMutex, CRYPTO_num_locks());
  for (i = 0; i < CRYPTO_num_locks(); i++)
    g_mutex_init(openssl_mutexes + i);

  SSL_library_init();
  CRYPTO_set_id_callback(openssl_thread_id_callback);
  CRYPTO_set_locking_callback(openssl_locking_callback);
}

#else

static GMutex** openssl_mutexes = NULL;

static void openssl_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    g_mutex_lock(openssl_mutexes[type]);
  else
    g_mutex_unlock(openssl_mutexes[type]);
}

static unsigned long openssl_thread_id_callback()
{
  unsigned long ret;
  ret = (unsigned long)g_thread_self();
  return ret;
}

static void init_openssl_locking()
{
  gint i;

  // initialize OpenSSL locking for multi-threaded operation
  openssl_mutexes = g_new(GMutex*, CRYPTO_num_locks());
  for (i = 0; i < CRYPTO_num_locks(); i++)
    openssl_mutexes[i] = g_mutex_new();

  SSL_library_init();
  CRYPTO_set_id_callback(openssl_thread_id_callback);
  CRYPTO_set_locking_callback(openssl_locking_callback);
}

#endif

static void init(void)
{
#if !GLIB_CHECK_VERSION(2, 32, 0)
  if (!g_thread_supported())
    g_thread_init(NULL);
#endif

  setlocale(LC_ALL, "");

#if !GLIB_CHECK_VERSION(2, 36, 0)
  g_type_init();
#endif

#ifndef G_OS_WIN32
  signal(SIGPIPE, SIG_IGN);
#endif

  init_openssl_locking();
}

static gchar* input_password(void)
{
  gint tries = 3;
  gchar buf[256];
  gchar* password = NULL;

#ifdef G_OS_WIN32
  HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE); 
  DWORD mode = 0;
  GetConsoleMode(hStdin, &mode);
  SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
#else
  struct termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  struct termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
#endif

again:
  g_print("Enter password for (%s): ", opt_username);
  if (fgets(buf, 256, stdin))
  {
    if (strlen(buf) > 1)
    {
      password = g_strndup(buf, strcspn(buf, "\r\n"));
    }
    else
    {
      if (--tries > 0)
      {
        g_print("\n");
        goto again;
      }

      g_print("\nYou need to provide non-empty password!\n");
      exit(1);
    }
  }
  else
  {
    g_printerr("\nERROR: Can't read password from the input!\n");
    exit(1);
  }

#ifdef G_OS_WIN32
  SetConsoleMode(hStdin, mode);
#else
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif

  g_print("\nGood, signing in...\n");

  return password;
}

void tool_init_bare(gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries)
{
  GError *local_err = NULL;

  init();

  opt_context = g_option_context_new(tool_name);
  if (tool_allow_unknown_options)
    g_option_context_set_ignore_unknown_options(opt_context, TRUE);
  if (tool_entries)
    g_option_context_add_main_entries(opt_context, tool_entries, NULL);
  g_option_context_add_main_entries(opt_context, basic_options, NULL);

  if (!g_option_context_parse(opt_context, ac, av, &local_err))
  {
    g_printerr("ERROR: Option parsing failed: %s\n", local_err->message);
    exit(1);
  }

  if (opt_version)
  {
    g_print("megatools " VERSION " - command line tools for Mega.co.nz\n\n");
    g_print("Written by Ondřej Jirman <megous@megous.com>, 2013\n");
    g_print("Go to http://megatools.megous.com for more information\n");
    exit(0);
  }
}

void tool_init(gint* ac, gchar*** av, const gchar* tool_name, GOptionEntry* tool_entries)
{
  GError *local_err = NULL;

  init();

  opt_context = g_option_context_new(tool_name);
  if (tool_allow_unknown_options)
    g_option_context_set_ignore_unknown_options(opt_context, TRUE);
  if (tool_entries)
    g_option_context_add_main_entries(opt_context, tool_entries, NULL);
  g_option_context_add_main_entries(opt_context, auth_options, NULL);
  g_option_context_add_main_entries(opt_context, basic_options, NULL);

  if (!g_option_context_parse(opt_context, ac, av, &local_err))
  {
    g_printerr("ERROR: Option parsing failed: %s\n", local_err->message);
    exit(1);
  }

  if (opt_version)
  {
    g_print("megatools " VERSION " - command line tools for Mega.co.nz\n\n");
    g_print("Written by Ondřej Jirman <megous@megous.com>, 2013\n");
    g_print("Go to http://megatools.megous.com for more information\n");
    exit(0);
  }

  // load username/password from ini file
  if (!opt_no_config || opt_config)
  {
    GKeyFile* kf = g_key_file_new();
    gchar* tmp = g_build_filename(g_get_home_dir(), MEGA_RC_FILENAME, NULL);
    gboolean status;

    if (opt_config)
      status = g_key_file_load_from_file(kf, opt_config, 0, NULL);
    else
      status = g_key_file_load_from_file(kf, tmp, 0, NULL) || g_key_file_load_from_file(kf, MEGA_RC_FILENAME, 0, NULL);

    if (status)
    {
      if (!opt_username)
        opt_username = g_key_file_get_string(kf, "Login", "Username", NULL);
      if(!opt_password)
        opt_password = g_key_file_get_string(kf, "Login", "Password", NULL);

      gint to = g_key_file_get_integer(kf, "Cache", "Timeout", &local_err);
      if (local_err == NULL)
        opt_cache_timout = to;
      else
        g_clear_error(&local_err);
    }
    g_free(tmp);
    g_key_file_free(kf);
  }

  if (!opt_username)
  {
    g_printerr("ERROR: You must specify your mega.co.nz username (email)\n");
    exit(1);
  }

  if (!opt_password && opt_no_ask_password)
  {
    g_printerr("ERROR: You must specify your mega.co.nz password\n");
    exit(1);
  }

  if (!opt_password)
    opt_password = input_password();
}

mega_session* tool_start_session(void)
{
  GError *local_err = NULL;
  gchar* sid = NULL;
  gboolean loaded = FALSE;

  mega_session* s = mega_session_new();

  // try to load cached session data (they are valid for 10 minutes since last
  // user_get or refresh)
  if (!mega_session_load(s, opt_username, opt_password, opt_cache_timout, &sid, &local_err))
  {
    g_clear_error(&local_err);

    if (!mega_session_open(s, opt_username, opt_password, sid, &local_err))
    {
      g_printerr("ERROR: Can't login to mega.co.nz: %s\n", local_err->message);
      goto err;
    }

    if (!mega_session_refresh(s, &local_err))
    {
      g_printerr("ERROR: Can't read filesystem info from mega.co.nz: %s\n", local_err->message);
      goto err;
    }

    loaded = TRUE;
    mega_session_save(s, NULL);
  }

  if (opt_reload_files && !loaded)
  {
    if (!mega_session_refresh(s, &local_err))
    {
      g_printerr("ERROR: Can't read filesystem info from mega.co.nz: %s\n", local_err->message);
      goto err;
    }

    mega_session_save(s, NULL);
  }

  g_free(sid);
  return s;

err:
  mega_session_free(s);
  g_clear_error(&local_err);
  g_free(sid);
  return NULL;
}

void tool_fini(mega_session* s)
{
  if (s)
    mega_session_free(s);

  g_option_context_free(opt_context);
  curl_global_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_free_strings();

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  g_free(openssl_mutexes);
}
