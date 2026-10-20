#define jail_c
#define LUA_CORE

#include "lprefix.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "lua.h"

#include "jail.h"
#include "lstate.h"



static const JailOption no_jail;  /* all zero: no restriction */

LUA_API const JailOption *lua_getjail (lua_State *L) {
  const JailOption *j = G(L)->jail;
  return (j != NULL) ? j : &no_jail;
}


/* strings are allocated with the state's allocator (not counted as GC debt) */
static int copystr (global_State *g, const char **dst, const char *src) {
  size_t l;
  char *s;
  *dst = NULL;
  if (src == NULL) return 1;
  l = strlen(src) + 1;
  s = (char *)(*g->frealloc)(g->ud, NULL, 0, l);
  if (s == NULL) return 0;
  memcpy(s, src, l);
  *dst = s;
  return 1;
}

static void freestr (global_State *g, const char *s) {
  if (s != NULL) (*g->frealloc)(g->ud, (void *)s, strlen(s) + 1, 0);
}

static void freejail (global_State *g, JailOption *j) {
  if (j == NULL) return;
  freestr(g, j->loadfile_root);
  freestr(g, j->ioroot);
  freestr(g, j->read_extension_allowlist);
  freestr(g, j->write_extension_allowlist);
  freestr(g, j->getenv_prefix);
  freestr(g, j->path_override);
  freestr(g, j->cpath_override);
  (*g->frealloc)(g->ud, j, sizeof(JailOption), 0);
}

LUA_API int lua_setjail (lua_State *L, const JailOption *opt, size_t size) {
  global_State *g = G(L);
  JailOption *j = NULL;
  if (size != sizeof(JailOption)) return 1;
  if (opt != NULL) {
    j = (JailOption *)(*g->frealloc)(g->ud, NULL, 0, sizeof(JailOption));
    if (j == NULL) return 1;
    *j = *opt;
    /* clear first so that 'freejail' is safe on failure */
    j->loadfile_root = j->ioroot = NULL;
    j->read_extension_allowlist = j->write_extension_allowlist = NULL;
    j->getenv_prefix = j->path_override = j->cpath_override = NULL;
    if (!copystr(g, &j->loadfile_root, opt->loadfile_root) ||
        !copystr(g, &j->ioroot, opt->ioroot) ||
        !copystr(g, &j->read_extension_allowlist, opt->read_extension_allowlist) ||
        !copystr(g, &j->write_extension_allowlist, opt->write_extension_allowlist) ||
        !copystr(g, &j->getenv_prefix, opt->getenv_prefix) ||
        !copystr(g, &j->path_override, opt->path_override) ||
        !copystr(g, &j->cpath_override, opt->cpath_override)) {
      freejail(g, j);
      return 1;
    }
  }
  freejail(g, g->jail);
  g->jail = j;
  return 0;
}

void luaJ_freejail (lua_State *L) {
  global_State *g = G(L);
  freejail(g, g->jail);
  g->jail = NULL;
}


int is_in_dir_allow_tmp (lua_State *L, const char *root, const char *f) {
  int is_in = is_in_dir(root, f);
  if (is_in || lua_getjail(L)->deny_tmp) return is_in;
  return is_in_tmp_dir(f);  /* allow tmp */
}


static int test_extension (const char *list, const char *fname) {
    if (!list) return 1;
    if (!fname) return 1;
    const char *dot = strrchr(fname, '.');
    if (dot == NULL || dot == fname || *(dot + 1) == '\0') return 0;
    const char *ext = dot + 1;
    char ext_[258];
    ext_[0] = ',';
    int i = 0;
    while (ext[i] != '\0') {
        if ((i + 1) >= sizeof(ext_) - 2) return 0;  /* too long to be listed */
        ext_[i + 1] = tolower((unsigned char)ext[i]);
        i++;
    }
    ext_[i + 1] = ',';
    ext_[i + 2] = '\0';
    return strstr(list, ext_) != NULL;
}
int test_read_extension_allowlist (lua_State *L, const char *fname) {
  return test_extension(lua_getjail(L)->read_extension_allowlist, fname);
}
int test_write_extension_allowlist (lua_State *L, const char *fname) {
  return test_extension(lua_getjail(L)->write_extension_allowlist, fname);
}
