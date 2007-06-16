#ifndef PKGDIR_DIRINDEX_H
#define PKGDIR_DIRINDEX_H
/* Directory index */

#include <trurl/narray.h>

struct pkgdir;
struct pkgdir_dirindex;

struct pkgdir_dirindex *pkgdir_dirindex_open(struct pkgdir *pkgdir);
void pkgdir_dirindex_close(struct pkgdir_dirindex *dirindex);

int pkgdir_dirindex_create(struct pkgdir *pkgdir);



/* returns packages having path */
tn_array *pkgdir_dirindex_get(const struct pkgdir_dirindex *dirindex,
                              tn_array *pkgs, const char *path);
/* path belongs to pkg? */
int pkgdir_dirindex_pkg_has_path(const struct pkgdir_dirindex *dirindex,
                                 const struct pkg *pkg, const char *path);

/* returns directories required by package */
tn_array *pkgdir_dirindex_get_reqdirs(const struct pkgdir_dirindex *dirindex,
                                      const struct pkg *pkg);


#endif