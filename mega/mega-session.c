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
 * SECTION:mega-session
 * @title 
 * @short_description: 
 *
 * Description...
 */

#include "mega-session.h"
#include "mega-api.h"
#include "mega-aes-key.h"
#include "mega-rsa-key.h"
#include "sjson.h"

struct _MegaSessionPrivate
{
  int dummy;
  MegaApi* api;
  MegaAesKey* password_key;
  MegaAesKey* master_key;
  MegaRsaKey* rsa_key;
  gchar* user_email;
  gchar* user_name;
  gchar* user_handle;
  gboolean is_open;
};

// {{{ GObject property and signal enums

enum MegaSessionProp
{
  PROP_0,
  PROP_API,
  PROP_PASSWORD_KEY,
  PROP_MASTER_KEY,
  PROP_RSA_KEY,
  PROP_USER_EMAIL,
  PROP_USER_NAME,
  PROP_USER_HANDLE,
  PROP_IS_OPEN,
  N_PROPERTIES
};

enum MegaSessionSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_session_new:
 *
 * Create new #MegaSession object.
 *
 * Returns: #MegaSession object.
 */
MegaSession* mega_session_new(void)
{
  MegaSession *session = g_object_new(MEGA_TYPE_SESSION, NULL);

  return session;
}

/**
 * mega_session_open:
 * @session: a #MegaSession
 * @username: 
 * @password: 
 * @session_id: 
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_open(MegaSession* session, const gchar* username, const gchar* password, const gchar* session_id, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(username != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(session_id != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  MegaSessionPrivate* priv = session->priv;
  //MegaAesKey *pkey, *mkey;

  // generate password key
  //pkey = mega_aes_key_new_from_password(password);

  //g_object_set(priv->api, "sid", session_id);

  //g_object_set(session, "master-key", mkey);
  //g_object_set(session, "password-key", pkey);

  return FALSE;
}

/**
 * mega_session_login:
 * @session: a #MegaSession
 * @username: 
 * @password: 
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_login(MegaSession* session, const gchar* username, const gchar* password, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(username != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  /*
		let r = this.api.call({
			a: 'us',
			uh: this.pkey.make_username_hash(username),
			user: username.toLowerCase()
		});

		this.mkey = Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
		if (!this.mkey.is_loaded()) {
			return false;
		}

		this.rsa = new Mega.RsaKey();
		if (!this.rsa.load_enc_privk(r.privk, this.mkey)) {
			return false;
		}

		let sid = this.rsa.decrypt_sid(r.csid);
		if (!sid) {
			return false;
		}

		this.api.setSessionId(sid);

		return this.loadUser();
*/
  return FALSE;
}

/**
 * mega_session_logout:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_logout(MegaSession* session, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  return FALSE;
}

/**
 * mega_session_close:
 * @session: a #MegaSession
 *
 * Description...
 *
 * Returns:
 */
gboolean mega_session_close(MegaSession* session)
{
  g_return_if_fail(MEGA_IS_SESSION(session));

  return FALSE;
}

/**
 * mega_session_save:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_save(MegaSession* session, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  return FALSE;
}

/**
 * mega_session_load:
 * @session: a #MegaSession
 * @username: 
 * @password: 
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_load(MegaSession* session, const gchar* username, const gchar* password, GError** error)
{
  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(username != NULL, FALSE);
  g_return_val_if_fail(password != NULL, FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  return FALSE;
}

/**
 * mega_session_get_user_info:
 * @session: a #MegaSession
 * @error: 
 *
 * Description...
 *
 * Returns: 
 */
gboolean mega_session_get_user_info(MegaSession* session, GError** error)
{
  GError *local_err = NULL;

  g_return_val_if_fail(MEGA_IS_SESSION(session), FALSE);
  g_return_val_if_fail(error == NULL || *error == NULL, FALSE);

  MegaSessionPrivate* priv = session->priv;

  gchar* user_info = mega_api_call(priv->api, "{\"a\":\"ug\"}", &local_err);
  if (!user_info)
  {
    g_propagate_error(error, local_err);
    return FALSE;
  }

  if (s_json_get_type(user_info) == S_JSON_TYPE_OBJECT)

  g_free(priv->user_handle);
  g_free(priv->user_email);
  g_free(priv->user_name);

  priv->user_handle = s_json_get_member_string(user_info, "h");
  priv->user_email = s_json_get_member_string(user_info, "e");
  priv->user_name = s_json_get_member_string(user_info, "n");

  priv->is_open = TRUE;

  g_free(user_info);

  gchar* key = s_json_get_member_string(user_info, "k");
  priv->master_key = mega_aes_key_new_from_enc_ubase64(key, priv->password_key);

    /*
		this.mkey = Mega.AesKey.new_from_enc_ubase64(r.k, this.pkey);
		if (!this.mkey.is_loaded()) {
			return false;
		}

		if (!this.rsa) {
			this.rsa = new Mega.RsaKey();
		}

		if (!this.rsa.load_enc_privk(r.privk, this.mkey)) {
			return false;
		}

		if (!this.rsa.load_pubk(r.pubk, this.mkey)) {
			return false;
		}

		return true;
                */
  return FALSE;
}

// {{{ GObject type setup

static void mega_session_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  switch (property_id)
  {
    case PROP_API:
      if (priv->api)
        g_object_unref(priv->api);
      priv->api = g_value_dup_object(value);
      break;

    case PROP_PASSWORD_KEY:
      if (priv->password_key)
        g_object_unref(priv->password_key);
      priv->password_key = g_value_dup_object(value);
      break;

    case PROP_MASTER_KEY:
      if (priv->master_key)
        g_object_unref(priv->master_key);
      priv->master_key = g_value_dup_object(value);
      break;

    case PROP_RSA_KEY:
      if (priv->rsa_key)
        g_object_unref(priv->rsa_key);
      priv->rsa_key = g_value_dup_object(value);
      break;

    case PROP_USER_EMAIL:
      g_free(priv->user_email);
      priv->user_email = g_value_dup_string(value);
      break;

    case PROP_USER_NAME:
      g_free(priv->user_name);
      priv->user_name = g_value_dup_string(value);
      break;

    case PROP_USER_HANDLE:
      g_free(priv->user_handle);
      priv->user_handle = g_value_dup_string(value);
      break;

    case PROP_IS_OPEN:
      priv->is_open = g_value_get_boolean(value);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_session_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  switch (property_id)
  {
    case PROP_API:
      g_value_set_object(value, priv->api);
      break;

    case PROP_PASSWORD_KEY:
      g_value_set_object(value, priv->password_key);
      break;

    case PROP_MASTER_KEY:
      g_value_set_object(value, priv->master_key);
      break;

    case PROP_RSA_KEY:
      g_value_set_object(value, priv->rsa_key);
      break;

    case PROP_USER_EMAIL:
      g_value_set_string(value, priv->user_email);
      break;

    case PROP_USER_NAME:
      g_value_set_string(value, priv->user_name);
      break;

    case PROP_USER_HANDLE:
      g_value_set_string(value, priv->user_handle);
      break;

    case PROP_IS_OPEN:
      g_value_set_boolean(value, priv->is_open);
      break;

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaSession, mega_session, G_TYPE_OBJECT);

static void mega_session_init(MegaSession *session)
{
  session->priv = G_TYPE_INSTANCE_GET_PRIVATE(session, MEGA_TYPE_SESSION, MegaSessionPrivate);

  session->priv->api = mega_api_new();
}

static void mega_session_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaSession *session = MEGA_SESSION(object);

  // Free everything that may hold reference to MegaSession

  G_OBJECT_CLASS(mega_session_parent_class)->dispose(object);
}

static void mega_session_finalize(GObject *object)
{
  MegaSession *session = MEGA_SESSION(object);
  MegaSessionPrivate *priv = session->priv;

  if (priv->api)
    g_object_unref(priv->api);
  if (priv->password_key)
    g_object_unref(priv->password_key);
  if (priv->master_key)
    g_object_unref(priv->master_key);
  if (priv->rsa_key)
    g_object_unref(priv->rsa_key);
  g_free(priv->user_email);
  g_free(priv->user_name);
  g_free(priv->user_handle);

  G_OBJECT_CLASS(mega_session_parent_class)->finalize(object);
}

static void mega_session_class_init(MegaSessionClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_session_set_property;
  gobject_class->get_property = mega_session_get_property;
  gobject_class->dispose = mega_session_dispose;
  gobject_class->finalize = mega_session_finalize;

  g_type_class_add_private(klass, sizeof(MegaSessionPrivate));

  /* object properties */

  param_spec = g_param_spec_object(
    /* name    */ "api",
    /* nick    */ "Api",
    /* blurb   */ "Set/get api",
    /* is_type */ MEGA_TYPE_API,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_API, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "password-key",
    /* nick    */ "Password-key",
    /* blurb   */ "Set/get password-key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_PASSWORD_KEY, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "master-key",
    /* nick    */ "Master-key",
    /* blurb   */ "Set/get master-key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_MASTER_KEY, param_spec);

  param_spec = g_param_spec_object(
    /* name    */ "rsa-key",
    /* nick    */ "Rsa-key",
    /* blurb   */ "Set/get rsa-key",
    /* is_type */ G_TYPE_OBJECT,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_RSA_KEY, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-email",
    /* nick    */ "User-email",
    /* blurb   */ "Set/get user-email",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_USER_EMAIL, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-name",
    /* nick    */ "User-name",
    /* blurb   */ "Set/get user-name",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_USER_NAME, param_spec);

  param_spec = g_param_spec_string(
    /* name    */ "user-handle",
    /* nick    */ "User-handle",
    /* blurb   */ "Set/get user-handle",
    /* default */ NULL,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_USER_HANDLE, param_spec);

  param_spec = g_param_spec_boolean(
    /* name    */ "is-open",
    /* nick    */ "Is-open",
    /* blurb   */ "Set/get is-open",
    /* default */ FALSE,
    /* flags   */ G_PARAM_READWRITE | G_PARAM_CONSTRUCT
  );

  g_object_class_install_property(gobject_class, PROP_IS_OPEN, param_spec);

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
