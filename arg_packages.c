/* 
   Copyright (C) 2000 - 2002 Pawel A. Gajda (mis@k2.net.pl)
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License published by
  the Free Software Foundation (see file COPYING for details).
*/

/*
  $Id$
*/

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <trurl/nassert.h>
#include <trurl/narray.h>
#include <trurl/nhash.h>
#include <trurl/nstr.h>
#include <trurl/nmalloc.h>
#include <trurl/n_snprintf.h>
#include <vfile/vfile.h>

#include "i18n.h"
#include "log.h"
#include "arg_packages.h"
#include "misc.h"
#include "pkgmisc.h"
#include "pkgset.h"
#include "pm/pm.h"

#define ARG_PACKAGES_SETUPDONE (1 << 0)

struct arg_packages {
    unsigned  flags;
    struct pm_ctx *pmctx;
    tn_array  *packages;        /*  */
    tn_array  *package_masks;   /* [@]foo(#|-)[VERSION[-RELEASE]] || foo.rpm   */
    tn_array  *package_lists;   /* --pset FILE */
    tn_hash   *resolved_caps;
    tn_array  *resolved_pkgs;
    tn_alloc  *na;
};

static 
char *prepare_pkgmask(const char *maskstr, const char *fpath, int nline)
{
    char               *p, *s[1024], *buf, mask[1024];
    const char         **tl, **tl_save;
    const char         *evrstr = NULL, *name = NULL, *virtname = NULL;
    const char         *version = NULL, *release = NULL;
    int32_t            epoch = 0;
    int                is_virtual;
    

    
    n_strdupap(maskstr, &buf);
    
    s[0] = NULL;
    
    p = strip(buf);
        
    if (*p == '\0' || *p == '#')
        return NULL;

    is_virtual = 0;
    while (*p && !isalnum(*p)) {
        switch (*p) {
            case '~':
            case '!':           /* for backward compatybility */
                break;
                
            case  '@':          /* optional */
                is_virtual = 1;
                break;
        }
        p++;
    }
    
    if (!isalnum(*p)) {
        if (nline > 0)
            logn(LOGERR, _("%s:%d: syntax error"), fpath, nline);
        else 
            logn(LOGERR, _("syntax error in package specification"));
        return NULL;
    }

    tl = tl_save = n_str_tokl(p, "#\t ");
    
    if (is_virtual) {
        virtname = tl[0];
        if (virtname) 
            name = tl[1];
        
        if (name) 
            evrstr = tl[2];
        
    } else {
        virtname = NULL;
        name = tl[0];
        evrstr = tl[1];
    }
        
    DBGF("virtname = %s, name = %s, evrstr = %s, %d\n",
         virtname, name, evrstr, tflags);
    
    if (evrstr) 
        poldek_util_parse_evr((char*)evrstr, &epoch, &version, &release);
        
                
    if (virtname) {
        n_snprintf(mask, sizeof(mask), "%s", virtname);
        
    } else {
        int n;
       
        n = n_snprintf(mask, sizeof(mask), name);
        if (version == NULL) {
            n_snprintf(&mask[n], sizeof(mask) - n, "-*");
           
        } else {
            n += n_snprintf(&mask[n], sizeof(mask) - n, "-%s", version);
            if (release)
                n_snprintf(&mask[n], sizeof(mask) - n, "-%s", release);
            else 
                n_snprintf(&mask[n], sizeof(mask) - n, "-*");
        }
    }
    
       
    n_str_tokl_free(tl_save);
    return n_strdup(mask);
}


struct arg_packages *arg_packages_new(struct pm_ctx *ctx) 
{
    struct arg_packages *aps;

    aps = n_malloc(sizeof(*aps));
    memset(aps, 0, sizeof(*aps));
    aps->pmctx = ctx;
    aps->packages = pkgs_array_new(64);
    aps->package_masks = n_array_new(64, free, (tn_fn_cmp)strcmp);
    aps->package_lists = n_array_new(64, free, (tn_fn_cmp)strcmp);
    aps->resolved_caps = n_hash_new(21, (tn_fn_free)n_array_free);
    aps->resolved_pkgs = pkgs_array_new_ex(128, pkg_cmp_name_evr_rev);
    return aps;
}

void arg_packages_free(struct arg_packages *aps) 
{
    n_array_free(aps->packages);
    n_array_free(aps->package_masks);
    n_array_free(aps->package_lists);
    n_hash_free(aps->resolved_caps);
    n_array_free(aps->resolved_pkgs);
    if (aps->na)
        n_alloc_free(aps->na);
    free(aps);
}

void arg_packages_clean(struct arg_packages *aps) 
{
    n_array_clean(aps->packages);
    n_array_clean(aps->package_masks);
    n_array_clean(aps->package_lists);
    n_hash_clean(aps->resolved_caps);
    n_array_clean(aps->resolved_pkgs);
    aps->flags = 0;
}


int arg_packages_size(struct arg_packages *aps) 
{
    return n_array_size(aps->package_masks) + n_array_size(aps->packages);
//        n_hash_size(aps->resolved_caps);
}

/* tries to convert N-[E:]V-R to N#[E:]V-R */
static char *mask2evrhashedmask(const char *mask) 
{
    const char *name, *ver, *rel, *p;
    char nmask[1024], e[32] = "", *tmp;
    int32_t epoch = 0;
    int n;
    
    n_strdupap(mask, &tmp);
    if (!poldek_util_parse_nevr(tmp, &name, &epoch, &ver, &rel))
        return NULL;
    
    p = ver;          /* check if it is really version */
    while (*p) {
        if (isdigit(*p))
            break;
        p++;
    }
    
    if (*p == '\0')    /* no digits => part of name propably */
        return NULL;
            
    if (epoch)
        snprintf(e, sizeof(e), "%d:", epoch);
    n = n_snprintf(nmask, sizeof(nmask), "%s#%s%s-%s", name, e, ver, rel);
    return n_strdupl(nmask, n);
}

tn_array *arg_packages_get_masks(struct arg_packages *aps, int hashed)
{
    tn_array *masks;
    int i;

    masks = n_array_clone(aps->package_masks);
    for (i=0; i < n_array_size(aps->package_masks); i++) {
        const char *mask;

        mask = n_array_nth(aps->package_masks, i);
        if (hashed && strchr(mask, '-') && strchr(mask, '*') == NULL) {
            char *nmask;

            if ((nmask = mask2evrhashedmask(mask)))
                mask = nmask;
        }
        n_array_push(masks, n_strdup(mask));
    }
    
    for (i=0; i < n_array_size(aps->packages); i++) {
        struct pkg *pkg = n_array_nth(aps->packages, i);
        char mask[1024], e[32] = "";
        int n;
        
        if (pkg->epoch)
            snprintf(e, sizeof(e), "%d:", pkg->epoch);
        
        n = n_snprintf(mask, sizeof(mask), "%s%s%s%s-%s", pkg->name,
                   hashed ? "#" : "-", e, pkg->ver, pkg->rel);
        n_array_push(masks, n_strdupl(mask, n));
    }
                   
    return masks;
}


int arg_packages_add_pkglist(struct arg_packages *aps, const char *path) 
{
    n_array_push(aps->package_lists, n_strdup(path));
    return 1;
}

int arg_packages_add_pkgmask(struct arg_packages *aps, const char *mask)
{
    
    n_array_push(aps->package_masks, n_strdup(mask));
    return 1;
}


int arg_packages_add_pkgmasks(struct arg_packages *aps, const tn_array *masks) 
{
    int i;
    for (i=0; i < n_array_size(masks); i++)
        n_array_push(aps->package_masks, n_strdup(n_array_nth(masks, i)));
    return 1;
}


static
int is_package_file(const char *path)
{
    struct stat st;
    
    if (strstr(path, ".rpm") == 0)
        return 0;

    return (stat(path, &st) == 0 && S_ISREG(st.st_mode));
}

int arg_packages_add_pkgfile(struct arg_packages *aps, const char *path)
{
    int rc = 1;
    
    if (!is_package_file(path))  
        rc = arg_packages_add_pkgmask(aps, path);
    
    else {
        struct pkg *pkg;
        
        if (aps->na == NULL)
            aps->na = n_alloc_new(4, TN_ALLOC_OBSTACK);
        
        pkg = pm_load_package(aps->pmctx, aps->na, path, PKG_LDNEVR);
        if (pkg == NULL)
            return 0;

        arg_packages_add_pkg(aps, pkg);
        pkg_free(pkg);
    }
    
    return rc;
}


int arg_packages_add_pkg(struct arg_packages *aps, struct pkg *pkg)
{
    n_array_push(aps->packages, pkg_link(pkg));
    return 1;
}


static 
int arg_packages_load_list(struct arg_packages *aps, const char *fpath)
{
    char buf[1024];
    struct vfile *vf;
    int nline, rc = 1;
    
    if ((vf = vfile_open(fpath, VFT_STDIO, VFM_RO)) == NULL) 
        return 0;

    nline = 0;
    while (fgets(buf, sizeof(buf), vf->vf_stream)) {
        char *mask;
        nline++;

        mask = prepare_pkgmask(strip(buf), fpath, nline);
        if (mask) 
            arg_packages_add_pkgmask(aps, mask);
    }
    
    vfile_close(vf);
    return rc;
}

int arg_packages_setup(struct arg_packages *aps)
{
    int i, rc = 1, n, nremoved;

    if (aps->flags & ARG_PACKAGES_SETUPDONE)
        return 1;
        
    for (i=0; i < n_array_size(aps->package_lists); i++) {
        char *path = n_array_nth(aps->package_lists, i);
        
        if (!arg_packages_load_list(aps, path))
            rc = 0;
    }
    
    n = n_array_size(aps->package_masks);
    n_array_sort(aps->package_masks);
    n_array_uniq(aps->package_masks);

    nremoved = n - n_array_size(aps->package_masks);
    n = n_array_size(aps->packages); 
    n_array_sort(aps->packages);
    n_array_uniq(aps->packages);

    nremoved += n - n_array_size(aps->packages);
    

    if (nremoved > 0)
        msgn(2, _("Removed %d duplicates from given packages"), nremoved); 

    aps->flags |= ARG_PACKAGES_SETUPDONE;
    
    return rc;
}

static
int resolve_bycap(struct arg_packages *aps, struct pkgset *ps, const char *mask)
{
    tn_array *pkgs;
    
    pkgs = pkgset_lookup_cap(ps, mask);
    if (pkgs == NULL || n_array_size(pkgs) == 0) {
        if (pkgs)
            n_array_free(pkgs);
        return 0;
    }
    
    if (poldek_VERBOSE > 1) {
        int i;
        
        msgn(2, "%s: %d package(s) found:", mask, n_array_size(pkgs));
        for (i=0; i < n_array_size(pkgs); i++)
            msgn(2, " - %s", pkg_snprintf_s(n_array_nth(pkgs, i)));
        
    }
    
    n_hash_insert(aps->resolved_caps, mask, pkgs);
    return n_array_size(pkgs);
}

static
int resolve_masks(tn_array *pkgs,
                  struct arg_packages *aps, tn_array *avpkgs,
                  struct pkgset *ps,
                  unsigned flags)
{
    int i, j, nmasks, rc = 1;
    int *matches, *matches_bycmp;
    
    nmasks = n_array_size(aps->package_masks);

    matches = alloca(nmasks * sizeof(*matches));
    memset(matches, 0, nmasks * sizeof(*matches));

    matches_bycmp = alloca(nmasks * sizeof(*matches_bycmp));
    memset(matches_bycmp, 0, nmasks * sizeof(*matches_bycmp));
    
    for (i=0; i < n_array_size(avpkgs); i++) {
        struct pkg *pkg = n_array_nth(avpkgs, i);

        for (j=0; j < nmasks; j++) {
            char *mask = n_array_nth(aps->package_masks, j);
            int  skip = 0;

            switch (*mask) {
                case '~':
                case '!':           /* for backward compatybility */
                    skip = 1;       /* optional package */
                    break;
                
                case  '@':
                    mask++;
                    break;
            }
            
            
            if (strcmp(mask, pkg->name) == 0) {
                n_array_push(pkgs, pkg_link(pkg));
                matches_bycmp[j]++;
                matches[j]++;
                
            } else if (fnmatch(mask, pkg->nvr, 0) == 0) {
                n_array_push(pkgs, pkg_link(pkg));
                matches[j]++;
                
            }
        }
    }
    
    
    for (j=0; j < n_array_size(aps->package_masks); j++) {
        const char *mask = n_array_nth(aps->package_masks, j);

        if (matches[j] == 0 && ps && (flags & ARG_PACKAGES_RESOLV_CAPS)) {
            if (resolve_bycap(aps, ps, mask)) {
                matches[j]++;
                continue;
            }
        }
        
        if (matches[j] == 0 && (flags & ARG_PACKAGES_RESOLV_MISSINGOK) == 0) {
            logn(LOGERR, _("%s: no such package"), mask);
            rc = 0;
        }

        if ((flags & ARG_PACKAGES_RESOLV_UNAMBIGUOUS) == 0 && matches_bycmp[j] > 1) {
            int pri = (flags & ARG_PACKAGES_RESOLV_EXACT) ? LOGERR : LOGWARN;
            logn(pri, _("%s: ambiguous name"), mask);
            if (flags & ARG_PACKAGES_RESOLV_EXACT)
                rc = 0;
        }
    }

    return rc;
}


static
int resolve_pkgs(tn_array *pkgs,
                 struct arg_packages *aps, tn_array *avpkgs, unsigned flags)
{
    int i, rc = 1;

    for (i=0; i < n_array_size(aps->packages); i++) {
        struct pkg *pkg, *spkg = n_array_nth(aps->packages, i);

        if ((pkg = n_array_bsearch(avpkgs, spkg)))
            n_array_push(pkgs, pkg_link(pkg));
        
        else if ((flags & ARG_PACKAGES_RESOLV_MISSINGOK) == 0) {
            logn(LOGERR, _("%s: no such package"), pkg_snprintf_s(spkg));
            rc = 0;
        }
    }
    
    return rc;
}


static int verify_pakcage_caps(struct arg_packages *aps, tn_array *resolved_pkgs) 
{
    tn_array *keys;
    int i, j;
    
    keys = n_hash_keys_cp(aps->resolved_caps);
    n_array_sort(resolved_pkgs);
    for (i=0; i < n_array_size(keys); i++) {
        const char *cap = n_array_nth(keys, i);
        tn_array *pkgs = n_hash_get(aps->resolved_caps, cap);
        for (j=0; j < n_array_size(pkgs); j++) {
            struct pkg *pkg = n_array_nth(pkgs, j);
            if (n_array_bsearch(resolved_pkgs, pkg)) {
                logn(LOGNOTICE, "%s: removed cap due to %s is marked",
                     cap, pkg_snprintf_s0(pkg));
                n_hash_remove(aps->resolved_caps, cap);
                break;
            }
        }
    }
    n_array_free(keys);
    return n_hash_size(aps->resolved_caps);
}


int arg_packages_resolve(struct arg_packages *aps,
                               tn_array *avpkgs, struct pkgset *ps,
                               unsigned flags)
{
    int i, j, nmasks, rc = 0;

    n_hash_clean(aps->resolved_caps);
    n_array_clean(aps->resolved_pkgs);
    
    nmasks = n_array_size(aps->package_masks);
    for (i=0; i < nmasks; i++) {
        char *mask = n_array_nth(aps->package_masks, i);
        int len = strlen(mask);
        
        if (len > 1 && mask[len - 1] == '-')
            mask[len - 1] = '\0';
        
        if (*mask == '*' && *(mask + 1) == '\0') {
            for (j=0; j < n_array_size(avpkgs); j++)
                n_array_push(aps->resolved_pkgs,
                             pkg_link(n_array_nth(avpkgs, j)));
            return n_array_size(aps->resolved_pkgs);
        }
    }
    
    rc = resolve_pkgs(aps->resolved_pkgs, aps, avpkgs, flags);
    if (rc)                     /* continue with masks */
        rc = resolve_masks(aps->resolved_pkgs, aps, avpkgs, ps, flags);

    if (!rc) {
        n_array_clean(aps->resolved_pkgs);
        n_hash_clean(aps->resolved_caps);
        
    } else {
        n_array_sort(aps->resolved_pkgs);
        n_array_uniq(aps->resolved_pkgs);
        
        if (flags & ARG_PACKAGES_RESOLV_UNAMBIGUOUS)
            n_array_uniq_ex(aps->resolved_pkgs, (tn_fn_cmp)pkg_cmp_uniq_name);
    }
    
    if (n_array_size(aps->resolved_pkgs))
        verify_pakcage_caps(aps, aps->resolved_pkgs);
    
    DBGF("ret %d pkgs\n", pkgs ? n_array_size(pkgs) : 0);
    return n_array_size(aps->resolved_pkgs) + n_hash_size(aps->resolved_caps);
}


tn_hash *arg_packages_get_resolved_caps(struct arg_packages *aps)
{
    return n_ref(aps->resolved_caps);
}

tn_array *arg_packages_get_resolved(struct arg_packages *aps)
{
    return n_array_dup(aps->resolved_pkgs, (tn_fn_dup)pkg_link);
}
