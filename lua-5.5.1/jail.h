#ifndef jail_h
#define jail_h

#include <stddef.h>

#include "lua.h"

/*
** implemented by the embedder (mlua)
** 'f' is a file name as passed to 'fopen' (decoded the same way, with
** links resolved); 'root' is UTF-8. They return 0 when unsure.
*/
extern int (is_in_dir) (const char *root, const char *f);
/* the temporary directory ('os.tmpname') */
extern int (is_in_tmp_dir) (const char *f);

typedef void (*lua_Package_Searchers_Modifier) (lua_State *L);

// debug
typedef struct DebugLibJailOption {
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
} DebugLibJailOption;

// TODO
// load
// rawequal, rawget, rawlen, rawset

/*
** Jail settings of a Lua state. All zero (NULL) means no restriction.
** Strings are copied by 'lua_setjail' and owned by the state.
** Keep in sync with mlua-sys (src/lua54/jail.rs).
*/
typedef struct JailOption {
    // loadfile / dofile
    const char *loadfile_root;
    // io
    const char *ioroot;
    // ",ext1,ext2," (lowercase)
    const char *read_extension_allowlist;
    const char *write_extension_allowlist;
    // allow getenv with prefixed env only
    const char *getenv_prefix;
    // package library
    const char *path_override;
    const char *cpath_override;
    lua_Package_Searchers_Modifier package_searchers_modifier;
    // os.clock
    lua_CFunction clock_overwrite;
    // string.rep
    size_t rep_max;
    int rep_max_limited;
    // os.clock
    int clock_precision;
    // loadfile / dofile from stdin
    unsigned char deny_load_stdin;
    // io stdin
    unsigned char deny_open_stdin;
    // popen / os.execute
    unsigned char deny_popen;
    // os.exit
    unsigned char deny_exit;
    // tmp
    unsigned char deny_tmp;
    // getenv
    unsigned char deny_getenv;
    // setlocale
    unsigned char deny_setlocale;
    // collectgarbage
    unsigned char deny_collectgarbage;
    // package library
    unsigned char deny_require;
    unsigned char deny_loadlib;
    unsigned char deny_searchpath;
    // os.time
    unsigned char deny_time;
    // load / loadfile / dofile / require: binary chunks
    unsigned char deny_binary_chunk;
    // debug
    DebugLibJailOption debug_option;
} JailOption;

/*
** Copy 'opt' into the state (NULL clears). 'size' must be sizeof(JailOption).
** Options read when a library is opened (package.path, package.searchers,
** io.stdin) must be set before opening the library.
** Returns 0 on success, non-zero on size mismatch or allocation failure
** (the previous setting is kept).
*/
LUA_API int (lua_setjail) (lua_State *L, const JailOption *opt, size_t size);
/* never NULL; returns an all-zero option if not jailed */
LUA_API const JailOption *(lua_getjail) (lua_State *L);

/* internal */
extern void (luaJ_freejail) (lua_State *L);
extern int (is_in_dir_allow_tmp) (lua_State *L, const char *root, const char *f);
extern int (test_read_extension_allowlist) (lua_State *L, const char *fname);
extern int (test_write_extension_allowlist) (lua_State *L, const char *fname);

#endif
