/* 
  Copyright (C) 2000 Pawel A. Gajda (mis@k2.net.pl)
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License published by
  the Free Software Foundation (see file COPYING for details).
*/

/*
  $Id$
*/

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <trurl/nassert.h>
#include <trurl/narray.h>
#include <trurl/nhash.h>

#include "i18n.h"
#include "log.h"
#include "pkg.h"
#include "pkgset.h"
#include "misc.h"
#include "pkgset-req.h"


static void mapfn_clean_pkg_color(struct pkg *pkg) 
{
    pkg_set_color(pkg, PKG_COLOR_WHITE);
    pkg_clr_prereqed(pkg);
}

/*
 * Ordering: sort packages topologically
 */
struct visit_install_order_s {
    tn_array *ordered_pkgs;
    tn_array *stack;
    int nerrors;
};


static
int visit_install_order(struct visit_install_order_s *vs, struct pkg *pkg,
                        unsigned reqpkg_flag, int deep) 
{
    int i, last_stack_i = -1;

    deep += 2;
    
    pkg_set_color(pkg, PKG_COLOR_GRAY);
    if (pkg->reqpkgs == NULL || n_array_size(pkg->reqpkgs) == 0) {
        msg(4, "_\n");
        msg_i(4, deep, "_ visit %s -> (NO REQS)", pkg->name);
        goto l_end;
    }

    n_array_push(vs->stack, pkg);
    last_stack_i = n_array_size(vs->stack) - 1;
    
    if (poldek_VERBOSE > 2) {
        msg(4, "_\n");
        msg_i(4, deep, "_ visit %s -> (", pkg->name);
        for (i=0; i < n_array_size(pkg->reqpkgs); i++) {
            struct reqpkg *rp;	
            
            rp = n_array_nth(pkg->reqpkgs, i);
            msg(4, "_%s%s, ", (rp->flags & reqpkg_flag) ? "*" : "",
                rp->pkg->name);
            
            if (rp->flags & REQPKG_MULTI) {
                int n = 0;
                while (rp->adds[n]) {
                    msg(4, "_%s%s, ",
                        (rp->adds[n]->flags & reqpkg_flag) ? "*" : "",
                        rp->adds[n]->pkg->name);
                    n++;
                }
            }
        }
        msg(4, "_)\n");
        msg_i(4, deep, "_ {");
    }
    
    for (i=0; i < n_array_size(pkg->reqpkgs); i++) {
        struct reqpkg *rpkg, *rp;
        int n;

        n = 0;
        rpkg = rp = n_array_nth(pkg->reqpkgs, i);
        
        while (rp != NULL) {
            if (pkg_is_color(rp->pkg, PKG_COLOR_WHITE)) {
                if (rp->flags & reqpkg_flag) 
                    pkg_set_prereqed(rp->pkg);
                else
                    pkg_clr_prereqed(rp->pkg);
                
                if (reqpkg_flag == 0 || (rp->flags & reqpkg_flag))
                    visit_install_order(vs, rp->pkg, reqpkg_flag, deep);
            
            } else if (pkg_is_color(rp->pkg, PKG_COLOR_BLACK)) {
                msg(4, "_\n");
                msg_i(4, deep, "_   visited %s", rp->pkg->name);
                
            } else if (pkg_is_color(rp->pkg, PKG_COLOR_GRAY)) { /* cycle  */
                int is_loop = 0;
                
                if (rp->flags & reqpkg_flag) {
                    int j, n = 0, nprereqs = 0;
                    
                    for (j=n_array_size(vs->stack)-1; j >= 0; j--) {
                        struct pkg *p = n_array_nth(vs->stack, j);

                        if (p == rp->pkg)
                            break;

                        n++;

                        if (!pkg_is_prereqed(p))
                            break;

                        nprereqs++;
                    }
                    
                    if (n > 0 && n == nprereqs)
                        is_loop = 1;
                }
                
                if (is_loop) {
                    vs->nerrors++;
                    
                    if (poldek_VERBOSE > 2) {
                        msg(4, "\n");
                        msg_i(4, deep, "   cycle   %s -> %s", pkg->name,
                              rp->pkg->name);

                    } else {
                        int i, size, n = 0;
                        char *error;

                        size = n_array_size(vs->stack) * 128;
                        error = alloca(size);

                        n = 0;
                        n += n_snprintf(error, size, _("PreReq loop: "));
                        n += n_snprintf(&error[n], size - n, "%s", rp->pkg->name);
                        for (i=n_array_size(vs->stack)-1; i >= 0; i--) {
                            struct pkg *p = n_array_nth(vs->stack, i);
                            n += n_snprintf(&error[n], size - n, " <- %s", p->name);
                        }
                        log(LOGERR, "%s\n", error);
                    }
                    
                } else {
                    msg(4, "\n");
                    msg_i(4, deep, "   fakecycle   %s -> %s", pkg->name,
                          rp->pkg->name);
                }
                
            } else 
                n_assert(0);
            
            if (rpkg->flags & REQPKG_MULTI)
                rp = rpkg->adds[n++];
            else
                rp = NULL;
        }
    }
    
    if (poldek_VERBOSE > 3) {
        msg(4, "\n");
        msg_i(4, deep, "_ } ");
        msg(4, "_%s",  pkg->name);
        for (i=n_array_size(vs->stack)-2; i >= 0; i--) {
            struct pkg *p = n_array_nth(vs->stack, i);
            if (p != pkg)
                msg(4, "_ <- %s", p->name);
        }
    }
    msg(4, "_\n");

 l_end:
    pkg_set_color(pkg, PKG_COLOR_BLACK);
    pkg_clr_prereqed(pkg);
    msgn(4, "push %s", pkg_snprintf_s(pkg));
    n_array_push(vs->ordered_pkgs, pkg);
    if (last_stack_i != -1) 
        for (i=last_stack_i; i < n_array_size(vs->stack); i++) {
            pkg = n_array_pop(vs->stack);
            pkg_clr_prereqed(pkg);
        }
    
    return 0;
}

static int do_order(tn_array *pkgs, tn_array **ordered_pkgs,
                    unsigned reqpkg_flag)
{
    struct pkg *pkg;
    struct visit_install_order_s vs;
    int i;
    
    vs.ordered_pkgs = n_array_new(n_array_size(pkgs), NULL, NULL);
//                                  (tn_fn_free)pkg_free, NULL);
    vs.nerrors = 0;
    vs.stack = n_array_new(128, NULL, NULL);
    
    n_array_map(pkgs, (tn_fn_map1)mapfn_clean_pkg_color);

    for (i=0; i<n_array_size(pkgs); i++) {
        pkg = n_array_nth(pkgs, i);
        if (pkg_is_color(pkg, PKG_COLOR_WHITE)) {
            visit_install_order(&vs, pkg, reqpkg_flag, reqpkg_flag ? 1 : 0);
            n_array_clean(vs.stack);
        }
    }

    n_assert(n_array_size(vs.ordered_pkgs) == n_array_size(pkgs));

    n_assert(*ordered_pkgs == NULL);
    n_array_free(vs.stack);
    *ordered_pkgs = vs.ordered_pkgs;
    return vs.nerrors;
}


/* RET: number of detected loops  */
int packages_order(tn_array *pkgs, tn_array **ordered_pkgs, int ordertype)
{
    tn_array *ordered = NULL;
    int nloops, verbose;
    unsigned reqpkg_flag = 0;
    
    n_assert(n_array_ctl_get_cmpfn(pkgs) == (tn_fn_cmp)pkg_cmp_name_evr_rev);
    /* insertion sort - assuming pkgs are already sorted
       by pkg_cmp_pri_name_evr_rev() */
    n_array_isort_ex(pkgs, (tn_fn_cmp)pkg_cmp_pri_name_evr_rev);
    
    verbose = poldek_set_verbose(-10);
    do_order(pkgs, &ordered, 0);
    poldek_set_verbose(verbose);
    
    switch (ordertype) {
        case PKGORDER_INSTALL:
            reqpkg_flag = REQPKG_PREREQ;
            break;
            
        case PKGORDER_UNINSTALL:
            reqpkg_flag = REQPKG_PREREQ_UN;
            break;

        default:
            n_assert(0);
    }
    *ordered_pkgs = NULL;
    nloops = do_order(ordered, ordered_pkgs, reqpkg_flag);
    
    n_array_free(ordered);
    n_array_isort(pkgs);
    
    return nloops;
}



