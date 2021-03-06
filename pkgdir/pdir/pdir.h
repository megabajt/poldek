/*
  Copyright (C) 2000 - 2008 Pawel A. Gajda <mis@pld-linux.org>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2 as
  published by the Free Software Foundation (see file COPYING for details).

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef  POLDEK_PKGDIR_PDIR_H
#define  POLDEK_PKGDIR_PDIR_H

#include <sys/param.h>          /* for PATH_MAX */

#include <trurl/narray.h>
#include <trurl/nmalloc.h>
#include <vfile/vfile.h>

#include "misc.h"
#include "pkgdir.h"
#include "pkgdir_intern.h"

/* packages.dir digest */
#define PDIR_DIGEST_SIZE DIGEST_SIZE_SHA1

#define PDIR_DIGEST_MODE_DEFAULT      (1 << 1)
#define PDIR_DIGEST_MODE_v016         (1 << 2)

struct pdir_digest {
    struct vfile  *vf;
    unsigned      mode;
    char          mdh[PDIR_DIGEST_SIZE + 1]; /* header */
    char          mdd[PDIR_DIGEST_SIZE + 1]; /* data */
    char          *md;                   /* digest of whole data, v016 compat */
};

extern int pdir_v016compat;

struct pdir {
    struct vfile        *vf;
    char                idxpath[PATH_MAX];
    struct pdir_digest  *pdg;
    char                *mdd_orig;
};

void pdir_init(struct pdir *idx);
void pdir_destroy(struct pdir *idx);

#define FILEFMT_MAJOR 1
#define FILEFMT_MINOR 0

extern const char *pdir_digest_ext;
extern const char *pdir_digest_ext_v016;

int pdir_mkdigest_path(char *path, int size, const char *pathname,
                       const char *ext);

#define PDIR_DIGEST_SIZEx2 (2 * PDIR_DIGEST_SIZE)

struct pdir_digest *pdir_digest_new(const char *path, int vfmode,
                                    int v016compat, const char *pdir_name);
void pdir_digest_free(struct pdir_digest *pdg);

void pdir_digest_init(struct pdir_digest *pdg);
void pdir_digest_destroy(struct pdir_digest *pdg);

int pdir_digest_fill(struct pdir_digest *pdg, char *mdbuf, int size);

int pdir_digest_readfd(struct pdir_digest *pdg, int fd, const char *path);

int pdir_digest_verify(struct pdir_digest *pdg, struct vfile *vf);

int pdir_digest_create(struct pkgdir *pkgdir, const char *pathname,
                       int with_md);

int pdir_creat_md5(const char *pathname);
int pdir_verify_md5(const char *title, const char *pathname);


extern const char *pdir_default_pkgdir_name;
extern const char *pdir_packages_incdir;
extern const char *pdir_difftoc_suffix;

extern const char *pdir_poldeksindex;
extern const char *pdir_poldeksindex_toc;

extern const char *pdir_tag_depdirs;
extern const char *pdir_tag_ts;
extern const char *pdir_tag_ts_orig;
extern const char *pdir_tag_removed;
extern const char *pdir_tag_pkgroups;
extern const char *pdir_tag_endhdr;
extern const char *pdir_tag_endvarhdr;


int pdir_create(struct pkgdir *pkgdir, const char *pathname,
                unsigned flags);

struct pkg *pdir_pkg_restore(tn_alloc *na, tn_stream *st, struct pkg *pkg, 
                             tn_array *depdirs, unsigned ldflags,
                             struct pkg_offs *pkgo, const char *fn);

int pdir_pkg_store(const struct pkg *pkg, tn_stream *st, tn_array *depdirs,
                   unsigned flags);


extern const char *pdir_pkgstore_DEFAULT_ARCH;
extern const char *pdir_pkgstore_DEFAULT_OS;

const char *pdir_localidxpath(const struct pkgdir *pkgdir);

#endif /* POLDEK_PKGDIR_H*/
