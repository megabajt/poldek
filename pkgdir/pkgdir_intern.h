#ifndef POLDEK_PKGDIR_INTERNAL_H
#define POLDEK_PKGDIR_INTERNAL_H

#include <trurl/nbuf.h>

void pkgdir_setup_langs(struct pkgdir *pkgdir);
void pkgdir_setup_depdirs(struct pkgdir *pkgdir);
int  pkgdir_uniq(struct pkgdir *pkgdir);
char *pkgdir_setup_pkgprefix(const char *path);
int pkgdir_rmf(const char *dirpath, const char *mask);
//int pkgdir_make_idxpath(char *dpath, int size, const char *type,
//                        const char *path, const char *fn, const char *ext);
char *pkgdir_idxpath(char *dpath, int dsize,
                     const char *path, const char *type, const char *compress);

int pkgdir_cache_clean(const char *path, const char *mask);

#include "pkg_store.h"

/*  module methods */

typedef int (*pkgdir_fn_open)(struct pkgdir *pkgdir, unsigned flags);
typedef int (*pkgdir_fn_load)(struct pkgdir *pkgdir, unsigned ldflags);

typedef int (*pkgdir_fn_create)(struct pkgdir *pkgdir,
                                const char *path, unsigned flags);

enum pkgdir_uprc {
    PKGDIR_UPRC_NIL = 0,
    PKGDIR_UPRC_UPTODATE = 1,
    PKGDIR_UPRC_UPDATED  = 2,
    PKGDIR_UPRC_ERR_DESYNCHRONIZED = -1,
    PKGDIR_UPRC_ERR_UNKNOWN = -2, 
};


typedef int (*pkgdir_fn_update)(struct pkgdir *pkgdir, enum pkgdir_uprc *uprc);
typedef int (*pkgdir_fn_update_a)(const struct source *src,
                                  const char *idxpath);

typedef int (*pkgdir_fn_unlink)(const char *path, int allfiles);
typedef void (*pkgdir_fn_free)(struct pkgdir *pkgdir);

struct pkgdir_module {
    unsigned                    cap_flags;
    char                        *name;
    char                        **aliases;
    char                        *description;
    char                        *default_fn;
    char                        *default_compr;

    pkgdir_fn_open         open;
    pkgdir_fn_load         load;
    pkgdir_fn_create       create;
    pkgdir_fn_update       update;
    pkgdir_fn_update_a     update_a;
    pkgdir_fn_unlink       unlink;
    pkgdir_fn_free         free;
	
    int (*posthook_diff) (struct pkgdir*, struct pkgdir*, struct pkgdir*);
};

int pkgdir_mod_register(const struct pkgdir_module *mod);
const struct pkgdir_module *pkgdir_mod_find(const char *name);

#endif