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

#ifndef __MEGA_NODE_H__
#define __MEGA_NODE_H__

#include <glib-object.h>

#define MEGA_TYPE_NODE            (mega_node_get_type())
#define MEGA_NODE(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), MEGA_TYPE_NODE, MegaNode))
#define MEGA_NODE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass),  MEGA_TYPE_NODE, MegaNodeClass))
#define MEGA_IS_NODE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), MEGA_TYPE_NODE))
#define MEGA_IS_NODE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass),  MEGA_TYPE_NODE))
#define MEGA_NODE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj),  MEGA_TYPE_NODE, MegaNodeClass))

typedef struct _MegaNode MegaNode;
typedef struct _MegaNodeClass MegaNodeClass;
typedef struct _MegaNodePrivate MegaNodePrivate;

struct _MegaNode
{
  GObject parent;
  MegaNodePrivate* priv;
};

struct _MegaNodeClass
{
  GObjectClass parent_class;
};

G_BEGIN_DECLS

GType                   mega_node_get_type              (void) G_GNUC_CONST;

MegaNode*               mega_node_new                   (void);

G_END_DECLS

#endif
