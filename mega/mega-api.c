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

/**
 * SECTION:mega-api
 * @title 
 * @short_description: 
 *
 * Description...
 */

#include <stdlib.h>
#include <time.h>
#include "mega-api.h"
#include "mega-http-client.h"
#include "sjson.h"

struct _MegaApiPrivate
{
  MegaHttpClient* http;
  gint id;
  gchar* rid;

  gchar* sid;
  gchar* sid_param_name;
  gboolean debug;
  gchar* server;
};

// {{{ GObject property and signal enums

enum MegaApiProp
{
  PROP_0,
  PROP_SID,
  PROP_SID_PARAM_NAME,
  PROP_DEBUG,
  PROP_SERVER,
  N_PROPERTIES
};

enum MegaApiSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

static void print_node(const gchar* n, const gchar* prefix)
{
  gchar* pretty = s_json_pretty(n);
  g_print("%s%s\n", prefix, pretty);
  g_free(pretty);
}

static guchar* make_request_id(void)
{
  const gchar chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  gchar k[11] = {0};
  gint i;

  for (i = 0; i < 10; i++)
    k[i] = chars[rand() % sizeof(chars)];

  return g_strdup(k);
}

static const gchar* srv_error_to_string(gint code)
{
  switch (code) 
  {
    case MEGA_API_SERVER_ERROR_EINTERNAL           : return "EINTERNAL";
    case MEGA_API_SERVER_ERROR_EARGS               : return "EARGS";
    case MEGA_API_SERVER_ERROR_EAGAIN              : return "EAGAIN";
    case MEGA_API_SERVER_ERROR_ERATELIMIT          : return "ERATELIMIT";
    case MEGA_API_SERVER_ERROR_EFAILED             : return "EFAILED";
    case MEGA_API_SERVER_ERROR_ETOOMANY            : return "ETOOMANY";
    case MEGA_API_SERVER_ERROR_ERANGE              : return "ERANGE";
    case MEGA_API_SERVER_ERROR_EEXPIRED            : return "EEXPIRED";
    case MEGA_API_SERVER_ERROR_ENOENT              : return "ENOENT";
    case MEGA_API_SERVER_ERROR_ECIRCULAR           : return "ECIRCULAR";
    case MEGA_API_SERVER_ERROR_EACCESS             : return "EACCESS";
    case MEGA_API_SERVER_ERROR_EEXIST              : return "EEXIST";
    case MEGA_API_SERVER_ERROR_EINCOMPLETE         : return "EINCOMPLETE";
    case MEGA_API_SERVER_ERROR_EKEY                : return "EKEY";
    case MEGA_API_SERVER_ERROR_ESID                : return "ESID";
    case MEGA_API_SERVER_ERROR_EBLOCKED            : return "EBLOCKED";
    case MEGA_API_SERVER_ERROR_EOVERQUOTA          : return "EOVERQUOTA";
    case MEGA_API_SERVER_ERROR_ETEMPUNAVAIL        : return "ETEMPUNAVAIL";
    case MEGA_API_SERVER_ERROR_ETOOMANYCONNECTIONS : return "ETOOMANYCONNECTIONS";
    default                                        : return "EUNKNOWN";
  }
}

static gint srv_error_to_api_error(gint code)
{
  switch (code)
  {
    case MEGA_API_SERVER_ERROR_EINTERNAL           : return MEGA_API_ERROR_EINTERNAL;
    case MEGA_API_SERVER_ERROR_EARGS               : return MEGA_API_ERROR_EARGS;
    case MEGA_API_SERVER_ERROR_EAGAIN              : return MEGA_API_ERROR_EAGAIN;
    case MEGA_API_SERVER_ERROR_ERATELIMIT          : return MEGA_API_ERROR_ERATELIMIT;
    case MEGA_API_SERVER_ERROR_EFAILED             : return MEGA_API_ERROR_EFAILED;
    case MEGA_API_SERVER_ERROR_ETOOMANY            : return MEGA_API_ERROR_ETOOMANY;
    case MEGA_API_SERVER_ERROR_ERANGE              : return MEGA_API_ERROR_ERANGE;
    case MEGA_API_SERVER_ERROR_EEXPIRED            : return MEGA_API_ERROR_EEXPIRED;
    case MEGA_API_SERVER_ERROR_ENOENT              : return MEGA_API_ERROR_ENOENT;
    case MEGA_API_SERVER_ERROR_ECIRCULAR           : return MEGA_API_ERROR_ECIRCULAR;
    case MEGA_API_SERVER_ERROR_EACCESS             : return MEGA_API_ERROR_EACCESS;
    case MEGA_API_SERVER_ERROR_EEXIST              : return MEGA_API_ERROR_EEXIST;
    case MEGA_API_SERVER_ERROR_EINCOMPLETE         : return MEGA_API_ERROR_EINCOMPLETE;
    case MEGA_API_SERVER_ERROR_EKEY                : return MEGA_API_ERROR_EKEY;
    case MEGA_API_SERVER_ERROR_ESID                : return MEGA_API_ERROR_ESID;
    case MEGA_API_SERVER_ERROR_EBLOCKED            : return MEGA_API_ERROR_EBLOCKED;
    case MEGA_API_SERVER_ERROR_EOVERQUOTA          : return MEGA_API_ERROR_EOVERQUOTA;
    case MEGA_API_SERVER_ERROR_ETEMPUNAVAIL        : return MEGA_API_ERROR_ETEMPUNAVAIL;
    case MEGA_API_SERVER_ERROR_ETOOMANYCONNECTIONS : return MEGA_API_ERROR_ETOOMANYCONNECTIONS;
    default                                        : return MEGA_API_ERROR_OTHER;
  }
}

/**
 * mega_api_new:
 *
 * Create new #MegaApi object.
 *
 * Returns: #MegaApi object.
 */
MegaApi* mega_api_new(void)
{
  MegaApi *api = g_object_new(MEGA_TYPE_API, NULL);

  return api;
}

static gchar* api_call_single(MegaApi* api, const gchar* request, GError** err)
{
  MegaApiPrivate* priv;
  GError* local_err = NULL;
  gchar* url = NULL;
  GString* response = NULL;

  g_return_val_if_fail(MEGA_IS_API(api), NULL);
  g_return_val_if_fail(request != NULL, NULL);
  g_return_val_if_fail(err == NULL || *err == NULL, NULL);

  priv = api->priv;

  if (priv->debug)
    print_node(request, "-> ");

  // prepare URL
  priv->id++;
  if (priv->sid)
    url = g_strdup_printf("https://%s/cs?id=%u&%s=%s", priv->server, priv->id, priv->sid_param_name ? priv->sid_param_name : "sid", priv->sid);
  else
    url = g_strdup_printf("https://%s/cs?id=%u", priv->server, priv->id);

  response = mega_http_client_post_simple(priv->http, url, request, -1, &local_err);
  g_free(url);

  // handle http errors
  if (!response)
  {
    if (local_err->domain == MEGA_HTTP_CLIENT_ERROR && local_err->code == MEGA_HTTP_CLIENT_ERROR_CONNECTION_BROKEN)
    {
      if (priv->debug)
        g_print("<- %d (simulated)\n", MEGA_API_SERVER_ERROR_EAGAIN);

      // simulate EAGAIN response if server drops connection
      return g_strdup_printf("%d", MEGA_API_SERVER_ERROR_EAGAIN);
    }
    else
    {
      g_propagate_prefixed_error(err, local_err, "HTTP POST failed: ");
      return NULL;
    }
  }

  // decode JSON
  if (!s_json_is_valid(response->str))
  {
    g_set_error(err, MEGA_API_ERROR, MEGA_API_ERROR_OTHER, "Invalid response");
    g_string_free(response, TRUE);
    return NULL;
  }

  if (priv->debug)
    print_node(response->str, "<- ");

  return g_string_free(response, FALSE);
}

/**
 * mega_api_call:
 * @api: a #MegaApi
 * @request: Request JSON string
 * @error: Error
 *
 * Perform API request with EAGAIN handling.
 *
 * Returns: JSON string response.
 */
gchar* mega_api_call(MegaApi* api, const gchar* request, GError** error)
{
  GError* local_err = NULL;
  gchar* response;
  gint delay = 250000; // repeat after 250ms 500ms 1s ...

  g_return_val_if_fail(MEGA_IS_API(api), NULL);
  g_return_val_if_fail(request != NULL, NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);

  // some default rate limiting
  g_usleep(10000);

again:
  response = api_call_single(api, request, &local_err);
  if (!response) 
  {
    g_propagate_error(error, local_err);
    return NULL;
  }

  // if we are asked to repeat the call, do it with exponential backoff
  if (s_json_get_type(response) == S_JSON_TYPE_NUMBER)
  {
    gint64 error_code = s_json_get_int(response, 0);
    g_free(response);

    // if we have EAGAIN, repeat the call
    if (error_code == MEGA_API_SERVER_ERROR_EAGAIN)
    {
      g_usleep(delay);
      delay = delay * 2;

      if (delay > 8 * 1000 * 1000)
      {
        g_set_error(error, MEGA_API_ERROR, srv_error_to_api_error(error_code), "Server keeps asking us for EAGAIN, giving up");
        return NULL;
      }

      goto again;
    }
    else
    {
      g_set_error(error, MEGA_API_ERROR, srv_error_to_api_error(error_code), "API call failed with %s", srv_error_to_string(error_code));
      return NULL;
    }
  }
  else if (s_json_get_type(response) != S_JSON_TYPE_ARRAY)
  {
    g_set_error(error, MEGA_API_ERROR, MEGA_API_ERROR_OTHER, "Invalid response: %s", response);
    g_free(response);
    return NULL;
  }

  return response;
}

/**
 * mega_api_call_simple:
 * @api: a #MegaApi
 * @expects: 
 * @error: 
 * @format: 
 * @...: 
 *
 * Description...
 *
 * Returns: 
 */
gchar* mega_api_call_simple(MegaApi* api, gchar expects, GError** error, const gchar* format, ...)
{
  GError *local_err = NULL;
  gchar *request, *response, *node_copy, *error_prefix, *method = NULL;
  const gchar* node;
  va_list args;

  g_return_val_if_fail(MEGA_IS_API(api), NULL);
  g_return_val_if_fail(error == NULL || *error == NULL, NULL);
  g_return_val_if_fail(format != NULL, NULL);

  va_start(args, format);
  request = s_json_buildv(format, args);
  va_end(args);

  if (request == NULL || s_json_get_type(request) != S_JSON_TYPE_OBJECT || !s_json_path(request, ".a!string"))
  {
    g_set_error(error, MEGA_API_ERROR, MEGA_API_ERROR_OTHER, "Invalid request format: %s", request ? request : format);
    goto err0;
  }

  method = s_json_get_member_string(request, "a");

  // wrap request into an array
  request = s_json_build("[%J]", request);

  // gets us array of responses to our request
  response = mega_api_call(api, request, &local_err);
  if (!response)
  {
    g_propagate_prefixed_error(error, local_err, "API call '%s' failed: ", method);
    goto err0;
  }

  // check what we got
  node = s_json_get_element(response, 0);
  if (node)
  {
    SJsonType node_type = s_json_get_type(node);

    if (node_type == S_JSON_TYPE_NUMBER)
    {
      // if we got negative number it's error code
      gint64 v = s_json_get_int(node, 0);
      if (v < 0)
      {
        g_set_error(error, MEGA_API_ERROR, srv_error_to_api_error(v), "API call '%s' ended with error %s", method, srv_error_to_string(v));
        goto err1;
      }
    }

    if ((node_type == S_JSON_TYPE_OBJECT && expects == 'o') ||
        (node_type == S_JSON_TYPE_ARRAY && expects == 'a') ||
        (node_type == S_JSON_TYPE_STRING && expects == 's') ||
        (node_type == S_JSON_TYPE_NUMBER && expects == 'i') ||
        (node_type == S_JSON_TYPE_BOOL && expects == 'b') ||
        (node_type == S_JSON_TYPE_NULL && expects == 'n'))
    {
      // got it!
      node_copy = s_json_get(node);
      g_free(request);
      g_free(response);
      g_free(method);
      return node_copy;
    }

    g_set_error(error, MEGA_API_ERROR, MEGA_API_ERROR_OTHER, "API call '%s': Unexpected response type %d", method, node_type);
  }
  else
    g_set_error(error, MEGA_API_ERROR, MEGA_API_ERROR_OTHER, "API call '%s': Empty response", method);

err1:
  g_free(response);
err0:
  g_free(method);
  g_free(request);
  return NULL;
}

GQuark mega_api_error_quark(void)
{
  return g_quark_from_static_string("mega-api-error-quark");
}

// {{{ GObject type setup

static void mega_api_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaApi *api = MEGA_API(object);

  switch (property_id)
  {
    case PROP_SID:
      g_free(api->priv->sid);
      api->priv->sid = g_value_dup_string(value);
      break;

    case PROP_SID_PARAM_NAME:
      g_free(api->priv->sid_param_name);
      api->priv->sid_param_name = g_value_dup_string(value);
      break;

    case PROP_DEBUG:
      api->priv->debug = g_value_get_boolean(value);
      break;

    case PROP_SERVER:
      g_free(api->priv->server);
      api->priv->server = g_value_dup_string(value);
      if (!api->priv->server)
        api->priv->server = g_strdup("g.api.mega.co.nz");
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_api_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaApi *api = MEGA_API(object);

  switch (property_id)
  {
    case PROP_SID:
      g_value_set_string(value, api->priv->sid);
      break;

    case PROP_SID_PARAM_NAME:
      g_value_set_string(value, api->priv->sid_param_name);
      break;

    case PROP_DEBUG:
      g_value_set_boolean(value, api->priv->debug);
      break;

    case PROP_SERVER:
      g_value_set_string(value, api->priv->server);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaApi, mega_api, G_TYPE_OBJECT);

static void mega_api_init(MegaApi *api)
{
  api->priv = G_TYPE_INSTANCE_GET_PRIVATE(api, MEGA_TYPE_API, MegaApiPrivate);

  api->priv->http = mega_http_client_new();
  mega_http_client_set_content_type(api->priv->http, "application/json");

  api->priv->id = time(NULL);
  api->priv->rid = make_request_id();
}

static void mega_api_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaApi *api = MEGA_API(object);

  // Free everything that may hold reference to MegaApi

  G_OBJECT_CLASS(mega_api_parent_class)->dispose(object);
}

static void mega_api_finalize(GObject *object)
{
  MegaApi *api = MEGA_API(object);

  g_free(api->priv->rid);
  g_free(api->priv->sid);
  g_free(api->priv->sid_param_name);
  g_free(api->priv->server);

  G_OBJECT_CLASS(mega_api_parent_class)->finalize(object);
}

static void mega_api_class_init(MegaApiClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_api_set_property;
  gobject_class->get_property = mega_api_get_property;
  gobject_class->dispose = mega_api_dispose;
  gobject_class->finalize = mega_api_finalize;

  g_type_class_add_private(klass, sizeof(MegaApiPrivate));

  /* object properties */

  param_spec = g_param_spec_string(
    /* name    */ "sid",
    /* nick    */ "Sid",
    /* blurb   */ "Set/get session id",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_SID, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "sid-param-name",
    /* nick    */ "Sid-param-name",
    /* blurb   */ "Set/get session id parameter name",
    /* default */ "sid",
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_SID_PARAM_NAME, param_spec);

  param_spec = g_param_spec_boolean(
    /* name    */ "debug",
    /* nick    */ "Debug",
    /* blurb   */ "Set/get debug mode",
    /* default */ FALSE,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_DEBUG, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "server",
    /* nick    */ "Server",
    /* blurb   */ "Set/get API server address",
    /* default */ "g.api.mega.co.nz",
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_SERVER, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
