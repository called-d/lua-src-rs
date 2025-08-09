#ifndef jail_h
#define jail_h

#include "lobject.h"

extern int (is_in_dir) (const char *root, const char *f);
extern int (is_in_dir_allow_tmp) (const char *root, const char *f);

// loadfile / dofile
extern const char *(set_loadfileroot)(const char *loadfileroot_);
extern const char *(get_loadfileroot)();
// io
extern const char *(set_ioroot)(const char *ioroot_);
extern const char *(get_ioroot)();
// loadfile / dofile from stdin
extern void deny_load_stdin();
extern void allow_load_stdin();
extern int get_deny_load_stdin();
// io stdin
extern void deny_open_stdin();
extern void allow_open_stdin();
extern int get_deny_open_stdin();
// popen / os.execute
extern void deny_popen();
extern void allow_popen();
extern int get_deny_popen();
// os.exit
extern void deny_exit();
extern void allow_exit();
extern int get_deny_exit();
// tmp
extern void deny_tmp();
extern void allow_tmp();
extern int get_deny_tmp();
// getenv
extern void deny_getenv();
extern void allow_getenv();
extern int get_deny_getenv();
// allow getenv with prefixed env only
extern const char *(set_getenv_prefix)(const char *getenv_prefix_);
extern const char *(get_getenv_prefix)();
// setlocale
extern void deny_setlocale();
extern void allow_setlocale();
extern int get_deny_setlocale();
// collectgarbage()
extern void deny_collectgarbage();
extern void allow_collectgarbage();
extern int get_deny_collectgarbage();
// package library
extern void deny_require();
extern void allow_require();
extern int get_deny_require();
extern void deny_loadlib();
extern void allow_loadlib();
extern int get_deny_loadlib();
extern void deny_searchpath();
extern void allow_searchpath();
extern int get_deny_searchpath();
extern const char *(set_path_override)(const char *path_override_);
extern const char *(get_path_override)();
extern const char *(set_cpath_override)(const char *cpath_override_);
extern const char *(get_cpath_override)();
typedef void (*lua_Package_Searchers_Modifier) (lua_State *L);
extern lua_Package_Searchers_Modifier set_package_searchers_modifier_func(lua_Package_Searchers_Modifier f);
extern lua_Package_Searchers_Modifier get_package_searchers_modifier_func();
// os.time
extern void deny_time();
extern void allow_time();
extern int get_deny_time();
// string.rep
extern void set_rep_max(size_t max);
extern void reset_rep_max();
extern size_t get_rep_max();
// os.clock
extern void set_clock_precision(int p);
extern lua_CFunction set_clock_overwrite(lua_CFunction f);
extern int get_clock_precision();
extern lua_CFunction get_clock_overwrite();
// debug
typedef struct {
    unsigned char deny_debug;
    unsigned char deny_getuservalue;
    unsigned char deny_gethook;
    unsigned char deny_getinfo;
    unsigned char deny_getlocal;
    unsigned char deny_getregistry;
    unsigned char deny_getmetatable;
    unsigned char deny_getupvalue;
    unsigned char deny_upvaluejoin;
    unsigned char deny_upvalueid;
    unsigned char deny_setuservalue;
    unsigned char deny_sethook;
    unsigned char deny_setlocal;
    unsigned char deny_setmetatable;
    unsigned char deny_setupvalue;
    unsigned char deny_traceback;
    unsigned char deny_setcstacklimit;
} debug_lib_option_t;
extern void set_deny_debug_lib(debug_lib_option_t deny_list);
extern debug_lib_option_t get_deny_debug();
/* extern void deny_binary_io(); */
/* extern void allow_binary_io(); */
/* extern int get_deny_binary_io(); */
extern const char *(set_read_extension_allowlist)(const char *list);
extern int test_read_extension_allowlist(char *fname);
extern const char *(set_write_extension_allowlist)(const char *list);
extern int test_write_extension_allowlist(char *fname);
#endif
