/* 
  Copyright (C) 2000 - 2004 Pawel A. Gajda (mis@k2.net.pl)
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License published by
  the Free Software Foundation (see file COPYING for details).
*/

/*
  $Id$
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fnmatch.h>

#include <trurl/nassert.h>
#include <trurl/nstr.h>
#include <trurl/nbuf.h>
#include <trurl/nstream.h>
#include <trurl/n_snprintf.h>
#include <trurl/nmalloc.h>

#include <vfile/vfile.h>

#define PKGDIR_INTERNAL

#include "i18n.h"
#include "log.h"
#include "pkgdir.h"
#include "pkg.h"
#include "pkgu.h"
#include "pkgmisc.h"
#include "pkgroup.h"
#include "pndir.h"

static const char *pndir_DEFAULT_ARCH = "noarch";
static const char *pndir_DEFAULT_OS = "linux";


struct pndir_paths {
    char  path_main[PATH_MAX];
    char  path[PATH_MAX];
    char  path_md[PATH_MAX];
    char  path_dscr[PATH_MAX];
    char  fmt_dscr[PATH_MAX];
    char  path_diff_toc[PATH_MAX];
};

static
int difftoc_vaccum(const struct pndir_paths *paths);


char *pndir_mkidx_pathname(char *dest, size_t size, const char *pathname,
                           const char *suffix) 
{
    char *ext, *bn = NULL;
    int suffix_len;

    suffix_len = strlen(suffix);
    
    if (strlen(pathname) + suffix_len + 1 > size)
        return NULL;
    
    bn = n_basenam(pathname);
    if ((ext = strrchr(bn, '.')) == NULL || strcmp(ext, ".dir") == 0) {
        snprintf(dest, size, "%s%s", pathname, suffix);
        
    } else {
        int len = ext - pathname + 1;
        n_assert(len + suffix_len + strlen(ext) + 1 < size);
        n_strncpy(dest, pathname, len);
        strcat(dest, suffix);
        
        if (strstr(suffix, ext) == NULL)
            strcat(dest, ext);
        dest[size - 1] = '\0';
    }

    return dest;
}

static 
int fheader(char *hdr, size_t size, const char *name, struct pkgdir *pkgdir) 
{
    char datestr[128];
    int n;

    
    strftime(datestr, sizeof(datestr),
             "%a, %d %b %Y %H:%M:%S GMT", gmtime(&pkgdir->ts));
    
    n = n_snprintf(hdr, size, 
                   "# %s v%d.%d\n"
                   "# This file was generated by poldek " VERSION " on %s.\n"
                   "# PLEASE DO *NOT* EDIT or poldek will hate you.\n"
                   "# Contains %d packages",
                   name, FILEFMT_MAJOR, FILEFMT_MINOR,
                   datestr, pkgdir->pkgs ? n_array_size(pkgdir->pkgs) : 0);
    
    if (pkgdir->flags & PKGDIR_DIFF) {
        strftime(datestr, sizeof(datestr),
             "%a, %d %b %Y %H:%M:%S GMT", gmtime(&pkgdir->ts_orig));
        
        n += n_snprintf(&hdr[n], size - n, 
                        ", %d removed (diff from %s)",
                        pkgdir->removed_pkgs ?
                        n_array_size(pkgdir->removed_pkgs) : 0,
                        datestr);
    }
    
    n += n_snprintf(&hdr[n], size - n, "\n");
    return n;
}


static int do_unlink(const char *path) 
{
    struct stat st;
    
    if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        return vf_localunlink(path);
        
    return 0;
}

static void put_pndir_header(struct tndb *db, struct pkgdir *pkgdir) 
{
    char    buf[4096];
    int     n, i;
    
    n = fheader(buf, sizeof(buf), pndir_poldeksindex, pkgdir);
    tndb_put(db, pndir_tag_hdr, strlen(pndir_tag_hdr), buf, n);

    n = n_snprintf(buf, sizeof(buf), "%lu", pkgdir->ts);
    tndb_put(db, pndir_tag_ts, strlen(pndir_tag_ts), buf, n);

    if (pkgdir->flags & PKGDIR_DIFF) {
        n = n_snprintf(buf, sizeof(buf), "%lu", pkgdir->ts_orig);
        tndb_put(db, pndir_tag_ts_orig, strlen(pndir_tag_ts_orig), buf, n);
        
        if (pkgdir->removed_pkgs && n_array_size(pkgdir->removed_pkgs)) {
            char pkgkey[256];
            tn_buf *nbuf;
            int n;
            
            nbuf = n_buf_new(n_array_size(pkgdir->removed_pkgs) * 64);
            for (i=0; i < n_array_size(pkgdir->removed_pkgs); i++) {
                struct pkg *pkg = n_array_nth(pkgdir->removed_pkgs, i);
                n = pndir_make_pkgkey(pkgkey, sizeof(pkgkey), pkg);
                //n_buf_printf(nbuf, "%s ", pkg_evr_snprintf_s(pkg));
                n_buf_write(nbuf, pkgkey, n);
                n_buf_puts(nbuf, " ");
            }
            
            tndb_put(db, pndir_tag_removed, strlen(pndir_tag_removed),
                     n_buf_ptr(nbuf), n_buf_size(nbuf));
            n_buf_free(nbuf);
        }
    }

    if (pkgdir->depdirs && n_array_size(pkgdir->depdirs)) {
        tn_buf *nbuf = n_buf_new(n_array_size(pkgdir->depdirs) * 16);
        
        for (i=0; i<n_array_size(pkgdir->depdirs); i++) 
            n_buf_printf(nbuf, "%s:", (char*)n_array_nth(pkgdir->depdirs, i));
        
        tndb_put(db, pndir_tag_depdirs, strlen(pndir_tag_depdirs),
                 n_buf_ptr(nbuf), n_buf_size(nbuf) - 1); /* -1 - eat last ':' */
        
        n_buf_free(nbuf);
    }

    if (pkgdir->avlangs_h && n_hash_size(pkgdir->avlangs_h)) {
        tn_buf *nbuf = n_buf_new(n_hash_size(pkgdir->avlangs_h) * 3);
        tn_array *avlangs;

        avlangs = n_hash_keys(pkgdir->avlangs_h);
        
        for (i=0; i < n_array_size(avlangs); i++) 
            n_buf_printf(nbuf, "%s:", (char*)n_array_nth(avlangs, i));
        
        tndb_put(db, pndir_tag_langs, strlen(pndir_tag_langs),
                 n_buf_ptr(nbuf), n_buf_size(nbuf) - 1); /* -1 - eat last ':' */
        
        n_buf_free(nbuf);
    }

    if (pkgdir->pkgroups) {
        tn_buf *nbuf = n_buf_new(8192);
        pkgroup_idx_store(pkgdir->pkgroups, nbuf);
        tndb_put(db, pndir_tag_pkgroups, strlen(pndir_tag_pkgroups),
                 n_buf_ptr(nbuf), n_buf_size(nbuf));
        
        n_buf_free(nbuf);
    }
    

    tndb_put(db, pndir_tag_endhdr, strlen(pndir_tag_endhdr), "\n", 1);

}


int pndir_make_pkgkey(char *key, size_t size, const struct pkg *pkg)
{
    char epoch[32];
    int n, nn;
    
    *epoch = '\0';
    if (pkg->epoch)
        snprintf(epoch, sizeof(epoch), "%d:", pkg->epoch);
    
    n = n_snprintf(key, size, "%s#%s%s-%s#", pkg->name, epoch, pkg->ver,
                   pkg->rel);

    nn = n;

    if (pkg->arch && strcmp(pkg->arch, pndir_DEFAULT_ARCH) != 0)
        n += n_snprintf(&key[n], size - n, "%s", pkg->arch);

    if (pkg->os && strcmp(pkg->os, pndir_DEFAULT_OS) != 0)
        n += n_snprintf(&key[n], size - n, ":%s", pkg->os);


    if (nn == n) {              /* eat second '#' */
        n--;
        key[n] = '\0';
    }

    return n;
}


struct pkg *pndir_parse_pkgkey(char *key, int klen)
{
    char        *name;
    const char  *ver, *rel, *arch = NULL, *os = NULL;
    char        *evr, *buf, *p;
    int32_t     epoch;
    
    buf = alloca(klen + 1);
    memcpy(buf, key, klen + 1);
    
    if ((p = strchr(buf, '#')) == NULL)
        return NULL;
    
    *p = '\0';
    p++;

    name = buf;
    evr = p;
    
    if ((p = strchr(p, '#')) != NULL) {
        *p = '\0';
        p++;
        
        if (*p == ':') {
            p++;
            os = p;
            
        } else {
            arch = p;
            if ((p = strchr(p, ':')) != NULL) {
                *p = '\0';
                p++;
                os = p;
            }
        }
    }
    
    
    if (!parse_evr(evr, &epoch, &ver, &rel))
        return 0;
    
    if (ver == NULL || rel == NULL) {
        logn(LOGERR, _("%s:%s: failed to parse evr string"), name, evr);
        return NULL;
    }

    if (os == NULL)
        os = pndir_DEFAULT_OS;
    
    if (arch == NULL)
        arch = pndir_DEFAULT_ARCH;
    
    return pkg_new(name, epoch, ver, rel, arch, os); 
}

static
int difftoc_vaccum(const struct pndir_paths *paths)
{
    tn_array     *lines; 
    char         line[2048], *dn, *bn;
    char         tmp[PATH_MAX], difftoc_path_bak[PATH_MAX];
    struct stat  st_idx, st;
    struct vfile *vf;
    int          lineno, i, len;
    off_t        diffs_size;
    
    if (stat(paths->path_main, &st_idx) != 0) {
        logn(LOGERR, "vaccum: stat %s: %m", paths->path_main);
        return 0;
    }

    memcpy(tmp, paths->path_diff_toc, sizeof(tmp));
    n_basedirnam(tmp, &dn, &bn);

    
    if ((vf = vfile_open(paths->path_diff_toc, VFT_TRURLIO, VFM_RO)) == NULL)
        return 0;
    
    lines = n_array_new(128, NULL, NULL);
    while ((len = n_stream_gets(vf->vf_tnstream, line, sizeof(line))) > 0) {
        char *l;

        l = alloca(len + 1);
        memcpy(l, line, len + 1);
        n_array_push(lines, l);
        DBGF("l = [%s]\n", l);
    }
    
    if (n_array_size(lines)) {
        snprintf(difftoc_path_bak, sizeof(difftoc_path_bak), "%s-",
                 paths->path_diff_toc);
        rename(paths->path_diff_toc, difftoc_path_bak);
    }
    vfile_close(vf);

    if ((vf = vfile_open(paths->path_diff_toc, VFT_TRURLIO, VFM_RW)) == NULL) {
        rename(difftoc_path_bak, paths->path_diff_toc);
        n_array_free(lines);
        return 0;
    }

    
    lineno = 0;
    diffs_size = 0;
    for (i = n_array_size(lines) - 1; i >= 0; i--) {
        char *p, *l, path[PATH_MAX];

        l = n_array_nth(lines, i);
        if ((p = strchr(l, ' ')) == NULL) {
            logn(LOGERR, _("vaccum: %s: format error"), paths->path_diff_toc);
            *l = '\0';
            continue;
        }
        
        *p = '\0';
        /*  "- 1" to save space for ".md" (to unlink md too) */
        snprintf(path, sizeof(path) - 1, "%s/%s", dn, l);

        *p = ' ';
        
        if (stat(path, &st) != 0) {
            if (errno != ENOENT)
                logn(LOGERR, "vaccum diff: stat %s: %m", l);
            *l = '\0';
            continue;
        }
        DBGF("path = %s %ld, %ld, %ld\n", path, st.st_size, diffs_size,
             st_idx.st_size);
        
        if (lineno) {
            if (vf_valid_path(path)) {
                char *p;
                
                msgn(1, _("Removing outdated %s"), n_basenam(path));
                unlink(path);
                if ((p = strrchr(path, '.')) && strcmp(p, ".gz") == 0) {
                    strcpy(p, pndir_digest_ext);
                    //msgn(1, _("Removing outdated MDD %s"), n_basenam(path));
                    unlink(path);
                }
            }
            
        } else {
            if (diffs_size + st.st_size > (st_idx.st_size * 0.9))
                lineno = i;
            else
                diffs_size += st.st_size;
        }
    }

    for (i = lineno; i < n_array_size(lines); i++) {
        char *l;
        
        l = n_array_nth(lines, i);
        if (*l)
            n_stream_printf(vf->vf_tnstream, "%s", l);
    }

    vfile_close(vf);
    n_array_free(lines);
    return 1;
}

static
int difftoc_update(const struct pkgdir *pkgdir, const struct pndir_paths *paths)
{
    struct vfile   *vf;
    struct pndir   *idx;

    
    if ((vf = vfile_open(paths->path_diff_toc, VFT_TRURLIO, VFM_APPEND)) == NULL)
        return 0;

    idx = pkgdir->mod_data;
    n_assert(idx && idx->md_orig);
    n_stream_printf(vf->vf_tnstream, "%s %lu %s %lu\n", 
                    n_basenam(paths->path), pkgdir->ts,
                    idx->md_orig, pkgdir->ts_orig);
    vfile_close(vf);
    
    if (pkgdir->pkgs && n_array_size(pkgdir->pkgs))
        return difftoc_vaccum(paths);

    return 1;
}



    

static
int mk_paths(struct pndir_paths *paths, const char *path, struct pkgdir *pkgdir)
{
    char             suffix[64] = "", dscr_suffix[64] = "";
    char             dscr_suffix_fmt[128] = "", tmp[PATH_MAX];
    int              psize;

    memset(paths, 0, sizeof(paths));
    
    psize = PATH_MAX;
    snprintf(paths->path_main, psize, "%s", path);
    
    if ((pkgdir->flags & PKGDIR_DIFF) == 0) {
        snprintf(dscr_suffix, sizeof(dscr_suffix), "%s",
                 pndir_desc_suffix);

        snprintf(dscr_suffix_fmt, sizeof(dscr_suffix_fmt), "%s%%s%%s",
                 pndir_desc_suffix);
        
        snprintf(paths->path, psize, "%s", path);
        
    } else {
        char *dn, *bn, tsstr[32], temp[PATH_MAX];

        pndir_tsstr(tsstr, sizeof(tsstr), pkgdir->ts_orig);

        snprintf(suffix, sizeof(suffix), ".%s", tsstr);
        snprintf(dscr_suffix, sizeof(dscr_suffix), "%s.%s",
                 pndir_desc_suffix, tsstr);

        snprintf(dscr_suffix_fmt, sizeof(dscr_suffix_fmt), "%s%%s%%s.%s",
                 pndir_desc_suffix, tsstr);
        
        snprintf(temp, sizeof(temp), "%s", path);
        
        n_basedirnam(temp, &dn, &bn);
        if (!mk_dir(dn, pndir_packages_incdir))
            return 0;
		

        snprintf(tmp, psize, "%s/%s/%s", dn, pndir_packages_incdir, bn);

        if (pndir_mkidx_pathname(paths->path, psize, tmp, suffix) == NULL)
            return 0;

        snprintf(tmp, psize, "%s/%s/%s", dn, pndir_packages_incdir,
                 n_basenam(path));
        
        pndir_mkidx_pathname(paths->path_diff_toc, psize, tmp,
                             pndir_difftoc_suffix);
        path = tmp;
    }
    
    pndir_mkidx_pathname(paths->path_dscr, psize, path, dscr_suffix);
    pndir_mkidx_pathname(paths->fmt_dscr, psize, path, dscr_suffix_fmt);
    
#if ENABLE_TRACE
    printf("\nPATHS\n");
    printf("path_main  %s\n", paths->path_main);
    printf("path       %s\n", paths->path);
    printf("path_dscr  %s\n", paths->path_dscr);
    printf("path_dscrf %s\n", paths->fmt_dscr);
    printf("path_toc   %s\n\n", paths->path_diff_toc);
#endif    
    return 1;
}

struct db_dscr_ent {
    char langp[32];
    char data[0];
};
              

struct db_dscr {
    struct tndb *db;
    tn_array    *spool;
    int         npackages;
};

void db_dscr_free(struct db_dscr *dbh) 
{
    if (dbh->db)
        tndb_close(dbh->db);
    free(dbh);
};

static
struct db_dscr *db_dscr_open(const char *pathtmpl, const char *lang) 
{
    struct db_dscr *dbh;
    struct tndb *tmpdb;
    char path[PATH_MAX], *dot = ".";
    const char *langstr = lang;
                    
    if (lang == NULL || strcmp(lang, "C") == 0) {
        langstr = "";
        dot = "";
    }

    snprintf(path, sizeof(path), pathtmpl, dot, langstr);
                    
    tmpdb = tndb_creat(path, PNDIR_COMPRLEVEL, TNDB_SIGN_DIGEST);
    if (tmpdb == NULL) {
        logn(LOGERR, "%s: %m\n", path);
        return 0;
    }
    dbh = n_malloc(sizeof(*dbh));
    dbh->db = tmpdb;
    dbh->npackages = 0;
    return dbh;
}

static
int pndir_save_pkginfo(int nth, struct pkguinf *pkgu, struct pkgdir *pkgdir,
                       tn_hash *db_dscr_h, const char *key, int klen,
                       tn_buf *nbuf, const char *pathtmpl)
{
    
    tn_array *langs = pkguinf_langs(pkgu);
    int i;

    for (i=0; i < n_array_size(langs); i++) {
        struct db_dscr *dbh;
        char *lang = n_array_nth(langs, i);
        
        if (n_hash_size(pkgdir->avlangs_h) > 0 &&
            !n_hash_exists(pkgdir->avlangs_h, lang)) {
            continue;
        }
                
        if ((dbh = n_hash_get(db_dscr_h, lang)) == NULL) {
            dbh = db_dscr_open(pathtmpl, lang);
            if (dbh == NULL)
                return 0;
            n_hash_insert(db_dscr_h, lang, dbh);
        }
                
        n_buf_clean(nbuf);
        if (dbh->db && pkguinf_store(pkgu, nbuf, lang)) {
            char dkey[512];
            const char *akey;
            int  dklen;
            
            if (strcmp(lang, "C") == 0) {
                akey = key;
                dklen = klen;
            }
                    
            tndb_put(dbh->db, key, klen, n_buf_ptr(nbuf), n_buf_size(nbuf));
            dbh->npackages++;
            n_buf_clean(nbuf);
            
            if (nth > n_array_size(pkgdir->pkgs) / 2) {
                double percent = (dbh->npackages * 100);
                percent /=  n_array_size(pkgdir->pkgs);
                if (percent < 10) {
                    msgn(2, _(" Omiting '%s' descriptions "
                              "(%d - %.1lf%% only)..."),
                         lang, dbh->npackages, percent);
                    tndb_unlink(dbh->db);
                    tndb_close(dbh->db);
                    dbh->db = NULL;
                }
            }
        }
    }
    return 1;
}


int pndir_m_create(struct pkgdir *pkgdir, const char *pathname, unsigned flags)
{
    struct tndb      *db = NULL;
    int              i, nerr = 0, save_descr = 0;
    struct pndir     *idx;
    tn_array         *keys = NULL;
    tn_buf           *nbuf = NULL;
    unsigned         pkg_st_flags = flags;
    tn_hash          *db_dscr_h = NULL;
    struct pndir_paths paths;
    

    idx = pkgdir->mod_data;
    if (pkgdir->ts == 0) 
        pkgdir->ts = time(0);

    if (pathname == NULL && idx && idx->_vf) 
        pathname = vfile_localpath(idx->_vf);

    if (pathname == NULL && pkgdir->idxpath)
        pathname = pkgdir->idxpath;

    n_assert(pathname);
    mk_paths(&paths, pathname, pkgdir);

    printf("flags %d\n", flags);
    msgn_tty(1, _("Writing %s..."), vf_url_slim_s(paths.path, 0));
    msgn_f(1, _("Writing %s..."), vf_url_slim_s(paths.path, 0));

    do_unlink(paths.path);
    db = tndb_creat(paths.path, PNDIR_COMPRLEVEL,
                    TNDB_NOHASH | TNDB_SIGN_DIGEST);
    if (db == NULL) {
        logn(LOGERR, "%s: %m\n", paths.path);
		nerr++;
		goto l_end;
    }
    
    put_pndir_header(db, pkgdir);

    if (pkgdir->pkgs == NULL)
        goto l_close;

    db_dscr_h = n_hash_new(21, (tn_fn_free)db_dscr_free);
    keys = n_array_new(n_array_size(pkgdir->pkgs), free, (tn_fn_cmp)strcmp);
    nbuf = n_buf_new(1024 * 256);

    pkg_st_flags = flags;
    pkg_st_flags |= PKGSTORE_NOEVR | PKGSTORE_NOARCH |
        PKGSTORE_NOOS | PKGSTORE_NODESC;

    save_descr = 0;
    if (pkgdir->avlangs_h && (flags & PKGDIR_CREAT_NODESC) == 0)
        save_descr = 1;
    
    mem_info(-1, "pndir_save start");
    for (i=0; i < n_array_size(pkgdir->pkgs); i++) {
        struct pkg         *pkg;
        struct pkguinf     *pkgu;
        char               key[512];
        int                klen;

        pkg = n_array_nth(pkgdir->pkgs, i);

        klen = pndir_make_pkgkey(key, sizeof(key), pkg);
        n_array_push(keys, n_strdupl(key, klen));

        n_buf_clean(nbuf);
        if (pkg_store(pkg, nbuf, pkgdir->depdirs, pkg_st_flags))
            tndb_put(db, key, klen, n_buf_ptr(nbuf), n_buf_size(nbuf));
        
        if (i % 1000 == 0)
            mem_info(-1, "pndir_save");

        if (save_descr && (pkgu = pkg_info(pkg))) {
            int v;
            
            v = pndir_save_pkginfo(i, pkgu, pkgdir, db_dscr_h, key, klen, nbuf,
                                   paths.fmt_dscr);
            pkguinf_free(pkgu);
            if (!v) {
                nerr++;
                goto l_close;
            }
        }
    }

 l_close:
	if (db) {
		tndb_close(db);
		db = NULL;
	}

    if (db_dscr_h) {
        struct db_dscr *dbh;
        tn_array *langs;
        int i;

        langs = n_hash_keys(db_dscr_h);
        for (i=0; i < n_array_size(langs); i++) {
            char *lang = n_array_nth(langs, i);
            if (strcmp(lang, "C") == 0)
                continue;
            
            dbh = n_hash_get(db_dscr_h, lang);
            if (dbh->db == NULL) /* closed earlier */
                continue;
            
            /* less than 20% of descriptions in language => don't save */
            if ((dbh->npackages * 100) / n_array_size(pkgdir->pkgs) < 20) {
                msgn(2, _(" Skipping '%s' descriptions (%d - %.1lf%% only)..."),
                     lang, dbh->npackages,
                     (dbh->npackages * 100.0) / n_array_size(pkgdir->pkgs));
                tndb_unlink(dbh->db);
                
            } else {
                const char *p = vf_url_slim_s(tndb_path(dbh->db), 0);
                msgn(2, _(" Writing %d '%s' descriptions %s..."),
                     dbh->npackages, lang, p);
            }
            tndb_close(dbh->db);
            dbh->db = NULL;
        }
    }
    
    if ((pkgdir->flags & PKGDIR_DIFF) == 0 && nerr == 0) {
        struct pndir_digest dg;
        
        if (!pndir_digest_calc(&dg, keys))
            nerr++;
        else if (!pndir_digest_save(&dg, paths.path))
            nerr++;
    }
    
    
    if (pkgdir->flags & PKGDIR_DIFF)
        difftoc_update(pkgdir, &paths);
	
 l_end:
    if (nbuf)
        n_buf_free(nbuf);
    
    if (keys) 
        n_array_free(keys);

    if (db_dscr_h)
        n_hash_free(db_dscr_h);

    mem_info(-1, "pndir_save END");
    return nerr == 0;
}


