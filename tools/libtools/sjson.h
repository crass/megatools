/** 
 * sjson - fast string based JSON parser/generator
 *
 * Written by Ondrej Jirman <megous@megous.com>, 2013
 * WWW: https://github.com/megous/sjson
 */

#ifndef __S_JSON_H__
#define __S_JSON_H__

#include <glib.h>

typedef enum
{
  S_JSON_TYPE_NONE = 0,
  S_JSON_TYPE_OBJECT,
  S_JSON_TYPE_ARRAY,
  S_JSON_TYPE_STRING,
  S_JSON_TYPE_NUMBER,
  S_JSON_TYPE_BOOL,
  S_JSON_TYPE_NULL,
  S_JSON_TYPE_INVALID
} SJsonType;

typedef struct _SJsonGen SJsonGen;

// parser

gboolean       s_json_is_valid              (const gchar* json);
gchar*         s_json_get                   (const gchar* json);

SJsonType      s_json_get_type              (const gchar* json);
const gchar*   s_json_get_element           (const gchar* json, guint index);
gchar**        s_json_get_elements          (const gchar* json);
const gchar*   s_json_get_member            (const gchar* json, const gchar* name);
gchar*         s_json_get_string            (const gchar* json);
gint64         s_json_get_int               (const gchar* json, gint64 fallback);
gdouble        s_json_get_double            (const gchar* json, gdouble fallback);
gboolean       s_json_get_bool              (const gchar* json);
gboolean       s_json_is_null               (const gchar* json);

gchar*         s_json_get_member_string     (const gchar* json, const gchar* name);
gint64         s_json_get_member_int        (const gchar* json, const gchar* name, gint64 fallback);
gdouble        s_json_get_member_double     (const gchar* json, const gchar* name, gdouble fallback);
gboolean       s_json_get_member_bool       (const gchar* json, const gchar* name);
gboolean       s_json_member_is_null        (const gchar* json, const gchar* name);

// generator

SJsonGen*      s_json_gen_new                   (void);

void           s_json_gen_start_object          (SJsonGen* json);
void           s_json_gen_end_object            (SJsonGen* json);

void           s_json_gen_start_array           (SJsonGen* json);
void           s_json_gen_end_array             (SJsonGen* json);

void           s_json_gen_json                  (SJsonGen* json, const gchar* v);
void           s_json_gen_build                 (SJsonGen* json, const gchar* fmt, ...);
void           s_json_gen_string                (SJsonGen* json, const gchar* v);
void           s_json_gen_int                   (SJsonGen* json, gint64 v);
void           s_json_gen_double                (SJsonGen* json, gdouble v);
void           s_json_gen_bool                  (SJsonGen* json, gboolean v);
void           s_json_gen_null                  (SJsonGen* json);

void           s_json_gen_member_json           (SJsonGen* json, const gchar* name, const gchar* v);
void           s_json_gen_member_build          (SJsonGen* json, const gchar* name, const gchar* fmt, ...);
void           s_json_gen_member_string         (SJsonGen* json, const gchar* name, const gchar* v);
void           s_json_gen_member_int            (SJsonGen* json, const gchar* name, gint64 v);
void           s_json_gen_member_double         (SJsonGen* json, const gchar* name, gdouble v);
void           s_json_gen_member_bool           (SJsonGen* json, const gchar* name, gboolean v);
void           s_json_gen_member_null           (SJsonGen* json, const gchar* name);
void           s_json_gen_member_array          (SJsonGen* json, const gchar* name);
void           s_json_gen_member_object         (SJsonGen* json, const gchar* name);

gchar*         s_json_gen_done                  (SJsonGen* json);

gchar*         s_json_buildv                    (const gchar* format, va_list args);
gchar*         s_json_build                     (const gchar* format, ...);

gchar*         s_json_pretty                    (const gchar* json);

const gchar*   s_json_path                      (const gchar* json, const gchar* path);

#endif
