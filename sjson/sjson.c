/**
 * sjson - fast string based JSON parser/generator library
 * Copyright (C) 2013  Ondřej Jirman <megous@megous.com>
 *
 * WWW: https://github.com/megous/sjson
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdio.h>
#include "sjson.h"

enum
{
  TOK_NONE = 0, // no more tokens
  TOK_OBJ_START,
  TOK_OBJ_END,
  TOK_ARRAY_START,
  TOK_ARRAY_END,
  TOK_COLON,
  TOK_COMMA,
  TOK_STRING,
  TOK_NOESC_STRING,
  TOK_NUMBER,
  TOK_FALSE,
  TOK_TRUE,
  TOK_NULL,
  TOK_INVALID
};

/*!re2c
  re2c:define:YYCTYPE  = "guchar";
  re2c:define:YYCURSOR = c;
  re2c:define:YYMARKER = m;
  re2c:yyfill:enable   = 0;
  re2c:yych:conversion = 1;
  re2c:indent:top      = 1;

  WS = [ \t\n\r]+;

  INT = ("0" | [1-9] [0-9]*);
  MINUS = "-";
  FRAC = ("." [0-9]+);
  EXP = [eE] [+-]? [0-9]+;
  NUMBER = MINUS? INT FRAC? EXP?;

  CHAR = [^\\"\000];
  CTL = "\\" ["\\/bfnrt];
  UNICODE = "\\u" [0-9a-fA-F]{4};
  STRING = "\"" (CHAR|CTL|UNICODE)* "\"";
  NOESC_STRING = "\"" (CHAR)* "\"";

  IDENT = [A-Za-z_-][a-zA-Z0-9_-]*;
*/

static gint s_json_get_token(const gchar* json, const gchar** start, const gchar** end)
{
  g_return_val_if_fail(json != NULL, FALSE);

  const guchar* c = (const guchar*)json;
  const guchar* m = NULL;
  const guchar* s;
  gint token;

  while (TRUE)
  {
    s = c;

/*!re2c
    WS { 
      continue; 
    }

    "{" {
      token = TOK_OBJ_START;
      goto done;
    }

    "}" {
      token = TOK_OBJ_END;
      goto done;
    }

    "[" {
      token = TOK_ARRAY_START;
      goto done;
    }

    "]" {
      token = TOK_ARRAY_END;
      goto done;
    }

    NOESC_STRING {
      token = TOK_NOESC_STRING;
      goto done;
    }

    STRING {
      token = TOK_STRING;
      goto done;
    }

    ":" {
      token = TOK_COLON;
      goto done;
    }

    "," {
      token = TOK_COMMA;
      goto done;
    }

    NUMBER {
      token = TOK_NUMBER;
      goto done;
    }

    "true" {
      token = TOK_TRUE;
      goto done;
    }

    "false" {
      token = TOK_FALSE;
      goto done;
    }

    "null" {
      token = TOK_NULL;
      goto done;
    }

    [\000] { 
      return TOK_NONE;
    }

    . | "\n" {
      return TOK_INVALID;
    }
*/
  }

done:
  if (start)
    *start = s;
  if (end)
    *end = c;
  return token;
}

static SJsonType token_to_type(gint token)
{
  switch (token)
  {
    case TOK_NONE        : return S_JSON_TYPE_NONE;
    case TOK_OBJ_START   : return S_JSON_TYPE_OBJECT;
    case TOK_ARRAY_START : return S_JSON_TYPE_ARRAY;
    case TOK_STRING      : return S_JSON_TYPE_STRING;
    case TOK_NOESC_STRING: return S_JSON_TYPE_STRING;
    case TOK_NUMBER      : return S_JSON_TYPE_NUMBER;
    case TOK_FALSE       : return S_JSON_TYPE_BOOL;
    case TOK_TRUE        : return S_JSON_TYPE_BOOL;
    case TOK_NULL        : return S_JSON_TYPE_NULL;
    default              : return S_JSON_TYPE_INVALID;
  }
}

// public api

static gboolean s_json_is_valid_inner(const gchar* json, const gchar** end)
{
  const gchar* next;
  gint token;

  g_return_val_if_fail(json != NULL, FALSE);
  
  token = s_json_get_token(json, NULL, &next);
  if (token == TOK_ARRAY_START)
  {
    const gchar* array_elem = next;
    const gchar* array_next = NULL;
    gboolean expect_comma = FALSE;

    while (TRUE)
    {
      // check end of array
      token = s_json_get_token(array_elem, NULL, &array_next);
      if (token == TOK_ARRAY_END)
      {
        if (end)
          *end = array_next;
        return TRUE;
      }

      if (expect_comma)
      {
        if (token == TOK_COMMA)
          array_elem = array_next; // skip comma
        else
          return FALSE;
      }

      // check element
      if (!s_json_is_valid_inner(array_elem, &array_elem))
        return FALSE;

      expect_comma = TRUE;
    }
  }
  else if (token == TOK_OBJ_START)
  {
    const gchar* obj_next = next;
    gboolean expect_comma = FALSE;

    while (TRUE)
    {
      // check end of object
      token = s_json_get_token(obj_next, NULL, &obj_next);
      if (token == TOK_OBJ_END)
      {
        if (end)
          *end = obj_next;

        return TRUE;
      }

      // eat comma
      if (expect_comma)
      {
        if (token != TOK_COMMA)
          return FALSE;

        token = s_json_get_token(obj_next, NULL, &obj_next);
      }

      // check member name and colon
      if (token != TOK_STRING && token != TOK_NOESC_STRING)
        return FALSE;

      token = s_json_get_token(obj_next, NULL, &obj_next);
      if (token != TOK_COLON)
        return FALSE;

      // check member value
      if (!s_json_is_valid_inner(obj_next, &obj_next))
        return FALSE;

      expect_comma = TRUE;
    }
  }
  else if (token == TOK_STRING || token == TOK_NOESC_STRING || token == TOK_NUMBER || token == TOK_FALSE || token == TOK_TRUE || token == TOK_NULL)
  {
    if (end)
      *end = next;
    return TRUE;
  }

  return FALSE;
}

gboolean s_json_is_valid(const gchar* json)
{
  const gchar* next;

  g_return_val_if_fail(json != NULL, FALSE);
  
  return s_json_is_valid_inner(json, &next) && s_json_get_token(next, NULL, NULL) == TOK_NONE;
}

gchar* s_json_get(const gchar* json)
{
  const gchar* next;
  const gchar* start = NULL;

  g_return_val_if_fail(json != NULL, NULL);
  
  if (s_json_is_valid_inner(json, &next))
  {
    s_json_get_token(json, &start, NULL); // must set start

    return g_strndup(start, next - start);
  }

  return NULL;
}

SJsonType s_json_get_type(const gchar* json)
{
  g_return_val_if_fail(json != NULL, S_JSON_TYPE_INVALID);

  return token_to_type(s_json_get_token(json, NULL, NULL));
}

const gchar* s_json_get_element_first(const gchar* json)
{
  const gchar* next_elem;
  gint token;

  g_return_val_if_fail(json != NULL, NULL);

  token = s_json_get_token(json, NULL, &next_elem);
  if (token != TOK_ARRAY_START)
    return NULL;

  if (s_json_get_token(next_elem, NULL, NULL) == TOK_ARRAY_END)
    return NULL;

  return next_elem;
}

const gchar* s_json_get_element_next(const gchar* iter)
{
  const gchar* next_elem;
  gint token;

  g_return_val_if_fail(iter != NULL, NULL);

  if (!s_json_is_valid_inner(iter, &next_elem))
    return NULL;

  token = s_json_get_token(next_elem, NULL, &next_elem);
  if (token != TOK_COMMA)
    return NULL;

  return next_elem;
}

const gchar* s_json_get_element(const gchar* json, guint index)
{
  guint current_index = 0;

  g_return_val_if_fail(json != NULL, NULL);

  S_JSON_FOREACH_ELEMENT(json, elem)

    if (current_index == index)
      return elem;

    current_index++;

  S_JSON_FOREACH_END()

  return NULL;
}

gchar** s_json_get_elements(const gchar* json)
{
  GPtrArray* arr;

  g_return_val_if_fail(json != NULL, NULL);

  arr = g_ptr_array_sized_new(64);

  S_JSON_FOREACH_ELEMENT(json, elem)
    g_ptr_array_add(arr, (gchar*)elem);
  S_JSON_FOREACH_END()

  g_ptr_array_add(arr, NULL);

  return (gchar**)g_ptr_array_free(arr, FALSE);
}

const gchar* s_json_get_member_first(const gchar* json, const gchar** value)
{
  const gchar* key;
  const gchar* colon;
  const gchar* val;
  gint token;

  g_return_val_if_fail(json != NULL, NULL);
  g_return_val_if_fail(value != NULL, NULL);

  if (s_json_get_token(json, NULL, &key) != TOK_OBJ_START)
    return NULL;

  token = s_json_get_token(key, NULL, &colon);
  if (token != TOK_STRING && token != TOK_NOESC_STRING)
    return NULL;

  if (s_json_get_token(colon, NULL, &val) != TOK_COLON)
    return NULL;

  *value = val;
  return key;
}

const gchar* s_json_get_member_next(const gchar** value)
{
  const gchar* comma;
  const gchar* key;
  const gchar* colon;
  const gchar* val;
  gint token;

  g_return_val_if_fail(value != NULL && *value != NULL, NULL);

  if (!s_json_is_valid_inner(*value, &comma))
    return NULL;

  if (s_json_get_token(comma, NULL, &key) != TOK_COMMA)
    return NULL;

  token = s_json_get_token(key, NULL, &colon);
  if (token != TOK_STRING && token != TOK_NOESC_STRING)
    return NULL;

  if (s_json_get_token(colon, NULL, &val) != TOK_COLON)
    return NULL;

  *value = val;
  return key;
}

const gchar* s_json_get_member(const gchar* json, const gchar* name)
{
  g_return_val_if_fail(json != NULL, NULL);
  g_return_val_if_fail(name != NULL, NULL);

  S_JSON_FOREACH_MEMBER(json, key, value)

    if (s_json_string_match(key, name))
      return value;

  S_JSON_FOREACH_END()

  return NULL;
}

gchar* s_json_get_string(const gchar* json)
{
  const gchar* start;
  const gchar* end;
  gint token;

  g_return_val_if_fail(json != NULL, NULL);

  token = s_json_get_token(json, &start, &end);
  if (token != TOK_STRING && token != TOK_NOESC_STRING)
    return NULL;

  if (token == TOK_NOESC_STRING)
    return g_strndup(start + 1, (end - start) - 2);

  GString* str = g_string_sized_new(end - start);
  const guchar* c = (const guchar*)start + 1;
  const guchar* m = NULL;
  const guchar* s;

  while (TRUE)
  {
    s = c;

/*!re2c
    CHAR+ {
      g_string_append_len(str, s, c - s);
      continue;
    }

    CTL {
      gchar ch = (gchar)s[1];

      if (ch == 'b')
        g_string_append_c(str, '\b');
      else if (ch == 'n')
        g_string_append_c(str, '\n');
      else if (ch == 'r')
        g_string_append_c(str, '\r');
      else if (ch == 't')
        g_string_append_c(str, '\t');
      else if (ch == 'f')
        g_string_append_c(str, '\f');
      else
        g_string_append_c(str, ch);

      continue;
    }

    UNICODE {
      guint ch = 0;
      sscanf(s + 2, "%4x", &ch);
      g_string_append_unichar(str, ch);
      continue;
    }

    "\"" {
      return g_string_free(str, FALSE);
    }

    . | "\n" | [\000] { 
      g_assert_not_reached();
    }
*/
  }

  return NULL;
}

gint64 s_json_get_int(const gchar* json, gint64 fallback)
{
  const gchar* start;
  const gchar* end;

  g_return_val_if_fail(json != NULL, fallback);

  if (s_json_get_token(json, &start, &end) != TOK_NUMBER)
    return fallback;

  gchar* str = g_alloca(end - start + 1);
  memcpy(str, start, end - start);
  str[end - start] = 0;

  gint64 v = fallback;
  sscanf(str, "%" G_GINT64_FORMAT, &v);
  return v;
}

gdouble s_json_get_double(const gchar* json, gdouble fallback)
{
  const gchar* start;
  const gchar* end;

  g_return_val_if_fail(json != NULL, fallback);

  if (s_json_get_token(json, &start, &end) != TOK_NUMBER)
    return fallback;

  gchar* str = g_alloca(end - start + 1);
  memcpy(str, start, end - start);
  str[end - start] = 0;

  gdouble v = fallback;
  sscanf(str, "%lf", &v);
  return v;
}

gboolean s_json_get_bool(const gchar* json)
{
  g_return_val_if_fail(json != NULL, FALSE);

  gint token = s_json_get_token(json, NULL, NULL);
  if (token == TOK_TRUE)
    return TRUE;

  return FALSE;
}

gboolean s_json_is_null(const gchar* json)
{
  g_return_val_if_fail(json != NULL, FALSE);

  gint token = s_json_get_token(json, NULL, NULL);
  if (token == TOK_NULL)
    return TRUE;

  return FALSE;
}

gboolean s_json_string_match(const gchar* json_str, const gchar* c_str)
{
  const gchar *start, *end;
  gint token;

  g_return_val_if_fail(json_str != NULL, FALSE);
  g_return_val_if_fail(c_str != NULL, FALSE);

  token = s_json_get_token(json_str, &start, &end);
  if (token == TOK_NOESC_STRING)
  {
    // fast path
    gsize json_len = ((end - start) - 2);
    gint rs = strncmp(start + 1, c_str, json_len);

    return rs == 0 ? strlen(c_str) == json_len : FALSE;
  }
  else if (token == TOK_STRING)
  {
    // slow path
    gchar* str = s_json_get_string(json_str);
    gint rs = strcmp(str, c_str);
    g_free(str);

    return rs == 0;
  }
  else
  {
    return FALSE;
  }
}

// helpers

gchar* s_json_get_member_string(const gchar* json, const gchar* name)
{
  g_return_val_if_fail(json != NULL, NULL);
  g_return_val_if_fail(name != NULL, NULL);

  const gchar* member = s_json_get_member(json, name);
  if (member)
    return s_json_get_string(member);

  return NULL;
}

gint64 s_json_get_member_int(const gchar* json, const gchar* name, gint64 fallback)
{
  g_return_val_if_fail(json != NULL, fallback);
  g_return_val_if_fail(name != NULL, fallback);

  const gchar* member = s_json_get_member(json, name);
  if (member)
    return s_json_get_int(member, fallback);

  return fallback;
}

gdouble s_json_get_member_double(const gchar* json, const gchar* name, gdouble fallback)
{
  g_return_val_if_fail(json != NULL, fallback);
  g_return_val_if_fail(name != NULL, fallback);

  const gchar* member = s_json_get_member(json, name);
  if (member)
    return s_json_get_double(member, fallback);

  return fallback;
}

gboolean s_json_get_member_bool(const gchar* json, const gchar* name)
{
  g_return_val_if_fail(json != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  const gchar* member = s_json_get_member(json, name);
  if (member)
    return s_json_get_bool(member);

  return FALSE;
}

gboolean s_json_member_is_null(const gchar* json, const gchar* name)
{
  g_return_val_if_fail(json != NULL, FALSE);
  g_return_val_if_fail(name != NULL, FALSE);

  const gchar* member = s_json_get_member(json, name);
  if (member)
    return s_json_is_null(member);

  return TRUE;
}

// generator api

struct _SJsonGen
{
  GString* str;
};

SJsonGen* s_json_gen_new(void)
{
  SJsonGen* gen = g_slice_new(SJsonGen);
  gen->str = g_string_sized_new(512);
  return gen;
}

static void strip_comma(SJsonGen* json)
{
  if (json->str->len > 0)
  {
    if (json->str->str[json->str->len - 1] == ',')
      g_string_truncate(json->str, json->str->len - 1);
  }
}

void s_json_gen_start_object(SJsonGen* json)
{
  g_return_if_fail(json != NULL);

  g_string_append_c(json->str, '{');
}

void s_json_gen_end_object(SJsonGen* json)
{
  g_return_if_fail(json != NULL);

  strip_comma(json);
  g_string_append(json->str, "},");
}


void s_json_gen_start_array(SJsonGen* json)
{
  g_return_if_fail(json != NULL);

  g_string_append_c(json->str, '[');
}

void s_json_gen_end_array(SJsonGen* json)
{
  g_return_if_fail(json != NULL);

  strip_comma(json);
  g_string_append(json->str, "],");
}


static void escape_string(GString* str, const gchar* v)
{
  g_return_if_fail(str != NULL);
  g_return_if_fail(v != NULL);

  const guchar* c = (const guchar*)v;
  const guchar* m = NULL;
  const guchar* s;

  g_string_append_c(str, '"');

  while (TRUE)
  {
    s = c;

/*!re2c
  [\n] { g_string_append(str, "\\n"); continue; }
  [\r] { g_string_append(str, "\\r"); continue; }
  [\b] { g_string_append(str, "\\b"); continue; }
  [\t] { g_string_append(str, "\\t"); continue; }
  [\f] { g_string_append(str, "\\f"); continue; }
  [\"] { g_string_append(str, "\\\""); continue; }
  [\\] { g_string_append(str, "\\\\"); continue; }

  [\000] { 
    break;
  }

  [^\n\r\b\t"\\\000]+ {
    g_string_append_len(str, (gchar*)s, c - s);
    continue;
  }
*/
  }

  g_string_append_c(str, '"');
}

void s_json_gen_build(SJsonGen* json, const gchar* fmt, ...)
{
  va_list args;
  gchar* v;

  g_return_if_fail(json != NULL);
  g_return_if_fail(fmt != NULL);

  va_start(args, fmt);
  v = s_json_buildv(fmt, args);
  va_end(args);

  s_json_gen_json(json, v);

  g_free(v);
}

void s_json_gen_json(SJsonGen* json, const gchar* v)
{
  g_return_if_fail(json != NULL);

  if (v)
  {
    g_string_append(json->str, v);
    g_string_append_c(json->str, ',');
  }
  else
    s_json_gen_null(json);
}

void s_json_gen_string(SJsonGen* json, const gchar* v)
{
  g_return_if_fail(json != NULL);

  if (v)
  {
    escape_string(json->str, v);
    g_string_append_c(json->str, ',');
  }
  else
    s_json_gen_null(json);
}

void s_json_gen_int(SJsonGen* json, gint64 v)
{
  g_return_if_fail(json != NULL);

  g_string_append_printf(json->str, "%" G_GINT64_FORMAT ",", v);
}

void s_json_gen_double(SJsonGen* json, gdouble v)
{
  g_return_if_fail(json != NULL);

  g_string_append_printf(json->str, "%lg,", v);
}

void s_json_gen_bool(SJsonGen* json, gboolean v)
{
  g_return_if_fail(json != NULL);

  g_string_append(json->str, v ? "true," : "false,");
}

void s_json_gen_null(SJsonGen* json)
{
  g_return_if_fail(json != NULL);

  g_string_append(json->str, "null,");
}


void s_json_gen_member_build(SJsonGen* json, const gchar* name, const gchar* fmt, ...)
{
  va_list args;
  gchar* v;

  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);
  g_return_if_fail(fmt != NULL);

  va_start(args, fmt);
  v = s_json_buildv(fmt, args);
  va_end(args);

  s_json_gen_member_json(json, name, v);

  g_free(v);
}

void s_json_gen_member_json(SJsonGen* json, const gchar* name, const gchar* v)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_json(json, v);
}

void s_json_gen_member_string(SJsonGen* json, const gchar* name, const gchar* v)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_string(json, v);
}

void s_json_gen_member_int(SJsonGen* json, const gchar* name, gint64 v)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_int(json, v);
}

void s_json_gen_member_double(SJsonGen* json, const gchar* name, gdouble v)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_double(json, v);
}

void s_json_gen_member_bool(SJsonGen* json, const gchar* name, gboolean v)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_bool(json, v);
}

void s_json_gen_member_null(SJsonGen* json, const gchar* name)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_null(json);
}

void s_json_gen_member_array(SJsonGen* json, const gchar* name)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_start_array(json);
}

void s_json_gen_member_object(SJsonGen* json, const gchar* name)
{
  g_return_if_fail(json != NULL);
  g_return_if_fail(name != NULL);

  s_json_gen_string(json, name);
  strip_comma(json);
  g_string_append_c(json->str, ':');
  s_json_gen_start_object(json);
}


gchar* s_json_gen_done(SJsonGen* json)
{
  g_return_val_if_fail(json != NULL, NULL);

  strip_comma(json);
  gchar* str = g_string_free(json->str, FALSE);
  g_slice_free(SJsonGen, json);

  if (s_json_is_valid(str))
    return str;

  g_free(str);
  return NULL;
}

// build

// formats:
// - % ? format
// format: sidbnjSJ

gchar* s_json_buildv(const gchar* format, va_list args)
{
  g_return_val_if_fail(format != NULL, NULL);

  GString* str = g_string_sized_new(strlen(format));
  const guchar* c = (const guchar*)format;
  const guchar* m = NULL;
  const guchar* s;

#define IS_NULLABLE (s[1] == '?')
#define FMT_FULL(arg_type, code_format, code_leave) \
  gboolean is_null = (IS_NULLABLE ? va_arg(args, gboolean) : FALSE); \
  gchar fmt = s[IS_NULLABLE ? 2 : 1]; \
  arg_type arg = va_arg(args, arg_type); \
  if (is_null) { \
    g_string_append(str, "null"); \
  } else { \
    code_format \
  } \
  code_leave \
  continue;

#define FMT(arg_type, code) FMT_FULL(arg_type, code, )

  while (TRUE)
  {
    s = c;

/*!re2c
    (WS | "{" | "}" | "[" | "]" | NOESC_STRING | STRING | ":" | "," | NUMBER | "true" | "false" | "null")+ {
      g_string_append_len(str, s, c - s);
      continue;
    }

    IDENT {
      g_string_append_c(str, '"');
      g_string_append_len(str, s, c - s);
      g_string_append_c(str, '"');
      continue;
    }

    FMT = "%" "?"?;

    FMT [sS] {
      FMT_FULL(gchar*, if (arg) escape_string(str, arg); else g_string_append(str, "null");, if (fmt == 'S') g_free(arg);)
    }

    FMT [jJ] {
      FMT_FULL(gchar*, 
        if (arg) {
          const gchar* end;
          if (s_json_is_valid_inner(arg, &end))
            g_string_append_len(str, arg, end - arg); 
          else
            g_string_append(str, "null");
        } else {
          g_string_append(str, "null");
        }, if (fmt == 'J') g_free(arg);)
    }

    FMT [i] {
      FMT(gint64, g_string_append_printf(str, "%" G_GINT64_FORMAT, arg);)
    }

    FMT [d] {
      FMT(gdouble, g_string_append_printf(str, "%lg" , arg);)
    }

    FMT [b] {
      FMT(gboolean, g_string_append(str, arg ? "true" : "false");)
    }

    [\000] { 
      break;   
    }

    . | "\n" {
      goto err;
    }
*/
  }

  if (s_json_is_valid(str->str))
    return g_string_free(str, FALSE);

err:
  g_string_free(str, TRUE);
  return NULL;
}

gchar* s_json_build(const gchar* format, ...)
{
  va_list args;
  gchar* json;

  g_return_val_if_fail(format != NULL, NULL);

  va_start(args, format);
  json = s_json_buildv(format, args);
  va_end(args);

  return json;
}

gchar* s_json_pretty(const gchar* json)
{
  const gchar* start;
  const gchar* end;
  GString *str, *ind;
  gchar* json_valid;

  g_return_val_if_fail(json != NULL, NULL);

  // validate and isolate
  json_valid = s_json_get(json);
  if (!json_valid)
    return NULL;

  start = json_valid;

  str = g_string_sized_new(strlen(json) * 2);
  ind = g_string_sized_new(50);

#define PUSH_INDENT() g_string_append_c(ind, '\t')
#define POP_INDENT() g_string_truncate(ind, MAX(ind->len - 1, 0))
#define INDENT() g_string_append_len(str, ind->str, ind->len)

  gint prev_token = TOK_NONE;
  while (TRUE)
  {
    gint token = s_json_get_token(start, &start, &end);
    if (token == TOK_NONE)
      break;
    gint next_token = s_json_get_token(end, NULL, NULL);

    if ((token == TOK_OBJ_END && prev_token != TOK_OBJ_START) || (token == TOK_ARRAY_END && prev_token != TOK_ARRAY_START && prev_token != TOK_OBJ_END))
    {
      g_string_append_c(str, '\n');
      POP_INDENT();
      INDENT();
    }

    g_string_append_len(str, start, end - start);

    if ((token == TOK_OBJ_START && next_token != TOK_OBJ_END) || (token == TOK_ARRAY_START && next_token != TOK_OBJ_START && next_token != TOK_ARRAY_END))
    {
      g_string_append_c(str, '\n');
      PUSH_INDENT();
      INDENT();
    }
    else if (token == TOK_COMMA)
    {
      if ((prev_token == TOK_OBJ_END && next_token == TOK_OBJ_START) || (prev_token == TOK_ARRAY_END && next_token == TOK_ARRAY_START))
      {
        g_string_append_c(str, ' ');
      }
      else
      {
        g_string_append_c(str, '\n');
        INDENT();
      }
    }
    else if (token == TOK_COLON)
    {
      g_string_append_c(str, ' ');
    }

    prev_token = token;
    start = end;
  }

  g_string_free(ind, TRUE);
  g_free(json_valid);

  return g_string_free(str, FALSE);
}


const gchar* s_json_path(const gchar* json, const gchar* path)
{
  const guchar* c = (const guchar*)path;
  const guchar* m = NULL;
  const guchar* s;
  const gchar* cur_node = json;

  g_return_val_if_fail(json != NULL, NULL);
  g_return_val_if_fail(path != NULL, NULL);

#define CHECK_TYPE(type) \
  if (cur_node && s_json_get_type(cur_node) == type) \
    return cur_node; \
  if ((!cur_node || s_json_get_type(cur_node) == S_JSON_TYPE_NULL) && s[0] == '?') \
    return "null"; \
  return NULL;

  while (TRUE)
  {
    s = c;

/*!re2c
    WS {
      // skip whitespace
      continue;
    }

    [\$] {
      // root
      cur_node = json;
      continue;
    }

    [.] IDENT {
      if (!cur_node || s_json_get_type(cur_node) != S_JSON_TYPE_OBJECT)
        return NULL;

      // zero terminate member name on stack
      gchar* name = g_alloca((c - s));
      memcpy(name, s + 1, c - (s + 1));
      name[c - (s + 1)] = '\0';

      cur_node = s_json_get_member(cur_node, name);
      continue;
    }

    "[" INT "]" {
      if (!cur_node || s_json_get_type(cur_node) != S_JSON_TYPE_ARRAY)
        return NULL;

      guint index;
      sscanf(s + 1, "%u", &index);

      cur_node = s_json_get_element(cur_node, index);
      continue;
    }

    TYPE = [!?];

    TYPE "n" "umber"? {
      CHECK_TYPE(S_JSON_TYPE_NUMBER)
    }

    TYPE "s" "tring"? {
      CHECK_TYPE(S_JSON_TYPE_STRING)
    }

    TYPE "i" "nteger"? {
      if (cur_node && s_json_get_type(cur_node) == S_JSON_TYPE_NUMBER)
      {
        const gchar *int_start, *int_end, *i;
        g_assert(s_json_get_token(cur_node, &int_start, &int_end) == TOK_NUMBER);
        for (i = int_start; i < int_end; i++)
          if (*i > '9' || *i < '0')
            return NULL;
        return cur_node;
      }

      if ((!cur_node || s_json_get_type(cur_node) == S_JSON_TYPE_NULL) && s[0] == '?')
        return "null";

      return NULL;
    }

    TYPE "b" "oolean"? {
      CHECK_TYPE(S_JSON_TYPE_BOOL)
    }

    TYPE "o" "bject"? {
      CHECK_TYPE(S_JSON_TYPE_OBJECT)
    }

    TYPE "a" "rray"? {
      CHECK_TYPE(S_JSON_TYPE_ARRAY)
    }

    [\000] { 
      break;
    }

    . | "\n" {
      return NULL;
    }
*/
  }

  return cur_node;
}

gchar* s_json_compact(const gchar* json)
{
  g_return_val_if_fail(json != NULL, NULL);

  GString* str = g_string_sized_new(strlen(json));
  const guchar* c = (const guchar*)json;
  const guchar* m = NULL;
  const guchar* s;

  while (TRUE)
  {
    s = c;

/*!re2c
    ("{" | "}" | "[" | "]" | NOESC_STRING | STRING | ":" | "," | NUMBER | "true" | "false" | "null")+ {
      g_string_append_len(str, s, c - s);
      continue;
    }

    WS {
      continue;
    }

    [\000] { 
      break;   
    }

    . | "\n" {
      goto err;
    }
*/
  }

  return g_string_free(str, FALSE);

err:
  g_string_free(str, TRUE);
  return NULL;
}
