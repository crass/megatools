/**
gboolean                mega_session_save               (MegaSession* session, GError** error);
 * SECTION:mega-node
 * @title 
 * @short_description: 
 *
 * Description...
 */

#include "mega-node.h"

struct _MegaNodePrivate
{
  int dummy;
};

// {{{ GObject property and signal enums

enum MegaNodeProp
{
  PROP_0,
  N_PROPERTIES
};

enum MegaNodeSignal
{
  N_SIGNALS
};

static guint signals[N_SIGNALS];

// }}}

/**
 * mega_node_new:
 *
 * Create new #MegaNode object.
 *
 * Returns: #MegaNode object.
 */
MegaNode* mega_node_new(void)
{
  MegaNode *node = g_object_new(MEGA_TYPE_NODE, NULL);

  return node;
}

// {{{ GObject type setup

static void mega_node_set_property(GObject *object, guint property_id, const GValue *value, GParamSpec *pspec)
{
  MegaNode *node = MEGA_NODE(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

static void mega_node_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
  MegaNode *node = MEGA_NODE(object);

  switch (property_id)
  {
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
  }
}

G_DEFINE_TYPE(MegaNode, mega_node, G_TYPE_OBJECT);

static void mega_node_init(MegaNode *node)
{
  node->priv = G_TYPE_INSTANCE_GET_PRIVATE(node, MEGA_TYPE_NODE, MegaNodePrivate);
}

static void mega_node_dispose(GObject *object)
{
  G_GNUC_UNUSED MegaNode *node = MEGA_NODE(object);

  // Free everything that may hold reference to MegaNode

  G_OBJECT_CLASS(mega_node_parent_class)->dispose(object);
}

static void mega_node_finalize(GObject *object)
{
  G_GNUC_UNUSED MegaNode *node = MEGA_NODE(object);


  G_OBJECT_CLASS(mega_node_parent_class)->finalize(object);
}

static void mega_node_class_init(MegaNodeClass *klass)
{
  GObjectClass *gobject_class = G_OBJECT_CLASS(klass);
  GParamSpec *param_spec;

  gobject_class->set_property = mega_node_set_property;
  gobject_class->get_property = mega_node_get_property;
  gobject_class->dispose = mega_node_dispose;
  gobject_class->finalize = mega_node_finalize;

  g_type_class_add_private(klass, sizeof(MegaNodePrivate));

  /* object properties */

  /* object properties end */

  /* object signals */

  /* object signals end */
}

// }}}
