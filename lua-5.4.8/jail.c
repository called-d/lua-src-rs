#define jail_c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "luaconf.h"
#include "jail.h"


#if !defined(LUA_USE_POSIX)	/* { */
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <fileapi.h>
const char *tmp_dir_root() {
    char* buffer = malloc(MAX_PATH + 1);
    DWORD r = GetTempPathA(MAX_PATH, buffer);
    return buffer;
}
#endif				/* } */

int is_in_dir_allow_tmp (const char *root, const char *f) {
  int is_in = is_in_dir(root, f);
  if (is_in || get_deny_tmp()) return is_in;
  /* allow tmp */
#if defined(LUA_USE_POSIX)
  return is_in_dir("/tmp/", f));
#else
  const char *tmproot = tmp_dir_root();
  is_in = is_in_dir(tmproot, f);
  free(tmproot);
  return is_in;
#endif
}

static const char *loadfileroot = NULL;
static const char *ioroot = NULL;
static int deny_load_stdin_ = 0;
static int deny_open_stdin_ = 0;
static int deny_popen_ = 0;
static int deny_exit_ = 0;
static int deny_tmp_ = 0;
static int deny_getenv_ = 0;
static const char *getenv_prefix = NULL;
static int deny_setlocale_ = 0;
static int deny_collectgarbage_ = 0;
static int deny_require_ = 0;
static int deny_loadlib_ = 0;
static int deny_searchpath_ = 0;
static int deny_time_ = 0;
static int rep_max_limited = 0;
static size_t rep_max = 0;
static int clock_precision = 0;
static lua_CFunction clock_overwrite = NULL;
static const char *path_override = NULL;
static const char *cpath_override = NULL;
static lua_Package_Searchers_Modifier lua_package_searchers_modifier = NULL;
static debug_lib_option_t debug_lib_deny_list;
static int deny_binary_io_ = 0;
static const char *read_extension_allowlist = NULL;
static const char *write_extension_allowlist = NULL;

LUALIB_API const char *set_loadfileroot(const char *loadfileroot_) {
  const char *old = loadfileroot;
  loadfileroot = loadfileroot_;
  return old;
}
const char *get_loadfileroot() { return loadfileroot; }

LUALIB_API const char *set_ioroot(const char *ioroot_) {
  const char *old = ioroot;
  ioroot = ioroot_;
  return old;
}
const char *get_ioroot() { return ioroot; }

LUALIB_API void allow_load_stdin() { deny_load_stdin_ = 0; }
LUALIB_API void deny_load_stdin() { deny_load_stdin_ = 1; }
int get_deny_load_stdin() { return deny_load_stdin_; }

LUALIB_API void allow_open_stdin() { deny_open_stdin_ = 0; }
LUALIB_API void deny_open_stdin() { deny_open_stdin_ = 1; }
int get_deny_open_stdin() { return deny_open_stdin_; }

LUALIB_API void allow_popen() { deny_popen_ = 0; }
LUALIB_API void deny_popen() { deny_popen_ = 1; }
int get_deny_popen() { return deny_popen_; }

LUALIB_API void allow_exit() { deny_exit_ = 0; }
LUALIB_API void deny_exit() { deny_exit_ = 1; }
int get_deny_exit() { return deny_exit_; }

LUALIB_API void allow_tmp() { deny_tmp_ = 0; }
LUALIB_API void deny_tmp() { deny_tmp_ = 1; }
int get_deny_tmp() { return deny_tmp_; }

LUALIB_API void allow_getenv() { deny_getenv_ = 0; }
LUALIB_API void deny_getenv() { deny_getenv_ = 1; }
int get_deny_getenv() { return deny_getenv_; }

LUALIB_API const char *set_getenv_prefix(const char *getenv_prefix_) {
  const char *old = getenv_prefix;
  getenv_prefix = getenv_prefix_;
  return old;
}
const char *get_getenv_prefix() { return getenv_prefix; }

LUALIB_API void allow_setlocale() { deny_setlocale_ = 0; }
LUALIB_API void deny_setlocale() { deny_setlocale_ = 1; }
int get_deny_setlocale() { return deny_setlocale_; }

LUALIB_API void allow_collectgarbage() { deny_collectgarbage_ = 0; }
LUALIB_API void deny_collectgarbage() { deny_collectgarbage_ = 1; }
int get_deny_collectgarbage() { return deny_collectgarbage_; }

LUALIB_API void deny_require() { deny_require_ = 0; }
LUALIB_API void allow_require() { deny_require_ = 1; }
int get_deny_require() { return deny_require_; }
LUALIB_API void deny_loadlib() { deny_loadlib_ = 0; };
LUALIB_API void allow_loadlib() { deny_loadlib_ = 1; };
int get_deny_loadlib() { return deny_loadlib_; }
LUALIB_API void deny_searchpath() { deny_searchpath_ = 0; };
LUALIB_API void allow_searchpath() { deny_searchpath_ = 1; };
int get_deny_searchpath() { return deny_searchpath_; }

LUALIB_API const char *set_path_override(const char *path_override_) {
  const char *old = path_override;
  path_override = path_override_;
  return old;
}
const char *get_path_override() { return path_override; }
LUALIB_API const char *set_cpath_override(const char *cpath_override_) {
  const char *old = cpath_override;
  cpath_override = cpath_override_;
  return old;
}
const char *get_cpath_override() { return cpath_override; }

LUALIB_API lua_Package_Searchers_Modifier set_package_searchers_modifier_func(lua_Package_Searchers_Modifier f) {
    lua_Package_Searchers_Modifier old = lua_package_searchers_modifier;
    lua_package_searchers_modifier = f;
    return old;
}
lua_Package_Searchers_Modifier get_package_searchers_modifier_func() { return lua_package_searchers_modifier; }

LUALIB_API void deny_time() { deny_time_ = 1; }
LUALIB_API void allow_time() { deny_time_ = 0; }
int get_deny_time() { return deny_time_; }
LUALIB_API void set_rep_max(size_t max) {
    rep_max_limited = 1;
    rep_max = max;
}
LUALIB_API void reset_rep_max() {
    rep_max_limited = 0;
    rep_max = 0;
}
size_t get_rep_max() { return rep_max; }
int get_rep_limited() { return rep_max_limited; }
LUALIB_API void set_clock_precision(int p) { clock_precision = p; }
int get_clock_precision() { return clock_precision; }
LUALIB_API lua_CFunction set_clock_overwrite(lua_CFunction f) {
    lua_CFunction old = clock_overwrite;
    clock_overwrite = f;
    return old;
}
lua_CFunction get_clock_overwrite() { return clock_overwrite; }

LUALIB_API void set_deny_debug_lib(debug_lib_option_t deny_list) {
    debug_lib_deny_list = deny_list;
}
debug_lib_option_t get_deny_debug() { return debug_lib_deny_list; }

/* LUALIB_API void deny_binary_io() { deny_binary_io_ = 1; } */
/* LUALIB_API void allow_binary_io() { deny_binary_io_ = 0; } */
/* int get_deny_binary_io() { return deny_binary_io_; } */

int test_extension(const char *list, char *fname) {
    if (!list) return 1;
    if (!fname) return 1;
    char *dot = strrchr(fname, '.');
    if (dot == NULL || dot == fname || *(dot + 1) == '\0') return 0;
    char *ext = dot + 1;
    char ext_[258];
    ext_[0] = ',';
    int i = 0;
    while (ext[i] != '\0' && (i + 1) < sizeof(ext_) - 1) {
        ext_[i + 1] = tolower((unsigned char)ext[i]);
        i++;
    }
    ext_[i + 1] = ',';
    ext_[i + 2] = '\0';
    return strstr(list, ext_) != NULL;
}
LUALIB_API const char *set_read_extension_allowlist(const char *list) {
  const char *old = read_extension_allowlist;
  read_extension_allowlist = list;
  return old;
}
int test_read_extension_allowlist(char *fname) { return test_extension(read_extension_allowlist, fname); }
LUALIB_API const char *set_write_extension_allowlist(const char *list) {
  const char *old = write_extension_allowlist;
  write_extension_allowlist = list;
  return old;
}
int test_write_extension_allowlist(char *fname) { return test_extension(write_extension_allowlist, fname); }