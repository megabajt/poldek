/*
  Copyright (C) 2000 - 2002 Pawel A. Gajda <mis@pld.org.pl>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2 as
  published by the Free Software Foundation (see file COPYING for details).

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/*
  $Id$
*/

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#define _GNU_SOURCE 1
#include <fnmatch.h>
#undef _GNU_SOURCE

#include <pcre.h>
#include <trurl/nassert.h>
#include <trurl/narray.h>
#include <trurl/nmalloc.h>
#include <sigint/sigint.h>

#include "i18n.h"
#include "log.h"
#include "pkg.h"
#include "pkgset.h"
#include "pkgset.h"
#include "misc.h"
#include "search.h"
#include "pkgu.h"
#include "cli.h"

static const unsigned char   *pcre_chartable = NULL;
static int                    pcre_established = 0;

#define PATTERN_FMASK   0
#define PATTERN_PCRE    1

struct pattern {
    int              type; 
    char             *regexp;
    int              fnmatch_flags;
    unsigned         pcre_flags;
    pcre             *pcre;
    pcre_extra       *pcre_extra;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state);
static int search(struct cmdarg *cmdarg);

#define OPT_PATTERN_PCRE   (1 << 10)

#define OPT_SEARCH_CAP     (1 << 0)
#define OPT_SEARCH_REQ     (1 << 1)
#define OPT_SEARCH_CNFL    (1 << 2)
#define OPT_SEARCH_OBSL    (1 << 3)
#define OPT_SEARCH_SUMM    (1 << 4)
#define OPT_SEARCH_DESC    (1 << 5)
#define OPT_SEARCH_FL      (1 << 6)
#define OPT_SEARCH_GROUP   (1 << 7)

#define OPT_SEARCH_ALL     (OPT_SEARCH_CAP  | OPT_SEARCH_REQ | OPT_SEARCH_CNFL |  \
                            OPT_SEARCH_OBSL | OPT_SEARCH_SUMM | OPT_SEARCH_DESC | \
                            OPT_SEARCH_FL | OPT_SEARCH_GROUP)

#define OPT_SEARCH_DEFAULT (OPT_SEARCH_SUMM | OPT_SEARCH_DESC)

/* options which requires packages.dir processing */
#define OPT_SEARCH_HDD     (OPT_SEARCH_SUMM | OPT_SEARCH_DESC | OPT_SEARCH_FL)


#define OPT_NO_SEARCHSW    OPT_PATTERN_PCRE

static struct argp_option options[] = {
    { "provides",  'p', 0, 0, N_("Search capabilities"), 1},
    { "requires",  'r', 0, 0, N_("Search requirements"), 1},
    { "conflicts", 'c', 0, 0, N_("Search conflicts"), 1},
    { "obsoletes", 'o', 0, 0, N_("Search obsolences"), 1},
    { "summary",   's', 0, 0, N_("Search summaries, urls and license"), 1},
    { "description", 'd', 0, 0, N_("Search descriptions"), 1},
    { "group",     'g', 0, 0, N_("Search groups"), 1 }, 
    { "files",     'f', 0, 0, N_("Search file list"), 1},
    { NULL,        'l', 0,  OPTION_ALIAS, 0, 1},
    { "all",       'a', 0, 0,
      N_("Search all described fields, the defaults are: -sd"), 1
    },
    { "perlre",    OPT_PATTERN_PCRE, 0, 0, N_("Threat PATTERN as Perl regular expression"), 1},
    {NULL, 'h', 0, OPTION_HIDDEN, "", 1 },
    { 0, 0, 0, 0, 0, 0 },
};


struct poclidek_cmd command_search = {
    0, 
    "search", N_("PATTERN [PACKAGE...]"), N_("Search packages"), 
    options, parse_opt,
    NULL, search,
    NULL, NULL,
    N_("With --perlre pattern must be supplied as:\n"
       "     <delimiter>perl-regexp<delimiter>[imsx]\n"
       "  For example to find the packages containing foo.bar do:\n"
       "     search --perlre /foo\\.bar/\n"
       "  See perlre(1) for more details.\n"), NULL
};

static
error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct cmdarg *cmdarg = state->input;

    switch (key) {
        case 'a':
            cmdarg->flags |= OPT_SEARCH_ALL;
            break;
            
        case 'c':
            cmdarg->flags |= OPT_SEARCH_CNFL;
            break;

        case 'l':
        case 'f':
            cmdarg->flags |= OPT_SEARCH_FL;
            break;

        case 'g':
            cmdarg->flags |= OPT_SEARCH_GROUP;
            break;
            
        case 'o':
            cmdarg->flags |= OPT_SEARCH_OBSL;
            break;
            
        case 'p':
            cmdarg->flags |= OPT_SEARCH_CAP;
            break;

        case 'r':
            cmdarg->flags |= OPT_SEARCH_REQ;
            break;
            
        case 's':
            cmdarg->flags |= OPT_SEARCH_SUMM;
            break;

        case 'd':
            cmdarg->flags |= OPT_SEARCH_DESC;
            break;

        case OPT_PATTERN_PCRE:
            cmdarg->flags |= OPT_PATTERN_PCRE;
            break;

            
        case ARGP_KEY_ARG:
            if (arg == NULL)
                break;
            
            //printf("arg = %s\n", arg);
            
            if (poldek_ts_get_arg_count(cmdarg->ts) == 0 && cmdarg->d == NULL) {
                struct pattern   *pt;
                char             *regexp = NULL;
                unsigned         flags = 0;
                
                if ((cmdarg->flags & OPT_PATTERN_PCRE) == 0) {
                    regexp = arg;
                    
                } else {
                    char             *p, delim, *lastp;
                    int              len;

                    p = arg;
                    delim = *arg;
#if 0                           /* allow any delimiter */
                    if (delim != '/' && delim != '|') {
                        argp_usage(state);
                        return EINVAL;
                    }
#endif                
                    len = strlen(p) - 1;
                    lastp = p + len;
                
                    if (strchr("imsx", *lastp) == NULL && *lastp != delim) {
                        argp_usage(state);
                        return EINVAL;
                    
                    }
                
                    regexp = p + 1;
                
                    if ((p = strrchr(regexp, delim)) == NULL) {
                        argp_usage(state);
                        return EINVAL;
                    }
                
                    *p = '\0';
                    p++;
                
                
                    while (*p) {
                        switch (*p) {
                            case 'i':
                                flags |= PCRE_CASELESS;
                                break;

                            case 'm':
                                flags |= PCRE_MULTILINE;
                                break;

                            case 's':
                                flags |= PCRE_DOTALL;
                                break;

                            case 'x':
                                flags |= PCRE_EXTENDED;
                                break;
                            
                            default:
                                logn(LOGERR, _("search: unknown "
                                               "regexp option -- %c"), *p);
                                argp_usage(state);
                                return EINVAL;
                        }
                        p++;
                    }
                }
                
                
                pt = n_malloc(sizeof(*pt));
                
                if (cmdarg->flags & OPT_PATTERN_PCRE)
                    pt->type = PATTERN_PCRE;
                else
                    pt->type = PATTERN_FMASK;
                
                pt->regexp = n_strdup(regexp);
                pt->fnmatch_flags = 0;
                pt->pcre_flags = flags;
                pt->pcre = NULL;
                pt->pcre_extra = NULL;
                
                cmdarg->d = pt;
                
                break;
            }
            
            
        default:
            return ARGP_ERR_UNKNOWN;
    }
    
    return 0;
}

static
void init_pcre(void) 
{
    if (pcre_established == 0) {
        pcre_malloc = n_malloc;
        pcre_free = free;
        pcre_chartable = pcre_maketables();
#if 0        
        if (pcre_chartable != NULL)
            printf("pcre_chartable ON: %s\n", pcre_chartable);
#endif        
        pcre_established = 1;
    }
}

static
int pattern_compile(struct pattern *pt, int ntimes) 
{
    const char       *pcre_err = NULL;
    int              pcre_err_off = 0;

    
    n_assert(pt->pcre == NULL);
    n_assert(pt->pcre_extra == NULL);

#ifdef FNM_CASEFOLD
    pt->fnmatch_flags |= FNM_CASEFOLD;
#endif    

    if (pt->type != PATTERN_PCRE)
        return 1;
    
    pt->pcre = pcre_compile(pt->regexp, pt->pcre_flags, &pcre_err,
                            &pcre_err_off, pcre_chartable);
    
    if (pt->pcre == NULL) {
        logn(LOGERR, _("search: pattern: %s:%d: %s"), pt->regexp,
            pcre_err_off, pcre_err);
        return 0;
    }

    if (ntimes > 10) {
        pt->pcre_extra = pcre_study(pt->pcre, PCRE_CASELESS, &pcre_err);
        if (pt->pcre_extra == NULL) {
            logn(LOGERR, _("search: pattern: %s: %s"), pt->regexp, pcre_err);
            return 0;
        }
    }
    return 1;
}

static
int pattern_match(struct pattern *pt, const char *s, int len) 
{
    int match = 0;

    if (len == 0)
        len = strlen(s);

    switch (pt->type) {
        case PATTERN_FMASK:
            n_assert(s[len] == '\0');
            match = (fnmatch(pt->regexp, s, pt->fnmatch_flags) == 0);
            break;
            
        case PATTERN_PCRE:
            if (pcre_exec(pt->pcre, pt->pcre_extra, s, len, 0, 0, NULL, 0) == 0)
                match = 1;
            break;

        default:
            n_assert(0);
            break;
    }
    
    return match;
}

static
void pattern_free(struct pattern *pt) 
{

    if (pt->regexp) {
        free(pt->regexp);
        pt->regexp = NULL;
    }

    
    if (pt->pcre) {
        free(pt->pcre);
        pt->pcre = NULL;
    }
    
    if (pt->pcre_extra) {
        free(pt->pcre_extra);
        pt->pcre_extra = NULL;
    }

    free(pt);
}


static int fl_match(tn_array *fl, struct pattern *pt) 
{
    int i, j, match = 0;
    

    for (i=0; i < n_array_size(fl); i++) {
        struct pkgfl_ent    *flent;
        char                path[PATH_MAX], *dn;
        int                 n;

        
        flent = n_array_nth(fl, i);
        dn = flent->dirname;

        if (*dn == '/') {
            n_assert(*(dn + 1) == '\0');
            n = n_snprintf(path, sizeof(path), dn);
        } else {
            n = n_snprintf(path, sizeof(path), "/%s/", dn);
        }

        for (j=0; j < flent->items; j++) {
            struct flfile *f = flent->files[j];
            int nn;

            if (S_ISLNK(f->mode)) {
                char *name;

                name = f->basename + strlen(f->basename) + 1;
                if ((match = pattern_match(pt, name, 0)))
                    goto l_end;
            }
            
            nn = n_snprintf(&path[n], sizeof(path) - n, "%s", f->basename);
            if ((match = pattern_match(pt, path, n + nn)))
                goto l_end;
        }
    }
    
 l_end:
    return match;
}


static int search_pkg_files(struct pkg *pkg, struct pattern *pt) 
{
    tn_array  *fl;
    void      *flmark;
    int       match = 0;


    if (pkg->fl && fl_match(pkg->fl, pt))
        return 1;

    flmark = pkgflmodule_allocator_push_mark();

    if ((fl = pkg_other_fl(pkg)) != NULL) {
        match = fl_match(fl, pt);
        n_array_free(fl);
    }
    
    pkgflmodule_allocator_pop_mark(flmark);
    
    return match;
}



static int pkg_match(struct pkg *pkg, struct pattern *pt, unsigned flags) 
{
    int i, match = 0;
    struct capreq *cr;
    char *p;

    
    if ((flags & OPT_SEARCH_CAP) && pkg->caps)
        for (i=0; i<n_array_size(pkg->caps); i++) {
            cr = n_array_nth(pkg->caps, i);
            p = capreq_name(cr);
            if ((match = pattern_match(pt, p, strlen(p))))
                goto l_end;
        }
    
    if ((flags & OPT_SEARCH_REQ) && pkg->reqs)
        for (i=0; i<n_array_size(pkg->reqs); i++) {
            cr = n_array_nth(pkg->reqs, i);
            p = capreq_name(cr);
            if ((match = pattern_match(pt, p, strlen(p))))
                goto l_end;
        }
    
    if ((flags & (OPT_SEARCH_CNFL | OPT_SEARCH_OBSL)) && pkg->cnfls)
        for (i=0; i<n_array_size(pkg->cnfls); i++) {
            int matchit = 0;
            
            cr = n_array_nth(pkg->cnfls, i);
            p = capreq_name(cr);
            
            if (cnfl_is_obsl(cr)) {
                if ((flags & OPT_SEARCH_OBSL))
                    matchit = 1;
                
            } else if (flags & OPT_SEARCH_CNFL) {
                matchit = 1;
            }
            
            if (matchit && (match = pattern_match(pt, p, strlen(p))))
                goto l_end;
        }

    if ((flags & OPT_SEARCH_GROUP) && (p = (char*)pkg_group(pkg))) {
        if ((match = pattern_match(pt, p, strlen(p))))
            goto l_end;
    }

    if (flags & (OPT_SEARCH_FL)) 
        if ((match = search_pkg_files(pkg, pt)))
            goto l_end;

    if (flags & (OPT_SEARCH_SUMM | OPT_SEARCH_DESC)) {
        struct pkguinf *pkgu;
        
        if ((pkgu = pkg_info(pkg)) == NULL) {
            logn(LOGERR, _("%s: load package info failed"), pkg_snprintf_s(pkg));
            
        } else {
            if (flags & OPT_SEARCH_SUMM) {
                if (pkgu->summary != NULL)
                    match = pattern_match(pt, pkgu->summary, strlen(pkgu->summary));
                
                if (!match && pkgu->license != NULL) 
                    match = pattern_match(pt, pkgu->license, strlen(pkgu->license));
                
                if (!match && pkgu->url != NULL)
                    match = pattern_match(pt, pkgu->url, strlen(pkgu->url));
            }
            
            if (!match && ((flags & OPT_SEARCH_DESC) && pkgu->description))
                match = pattern_match(pt, pkgu->description,
                                      strlen(pkgu->description));
            
            pkguinf_free(pkgu);
        }
        
    }

    
 l_end:
    return match;
}


static int search(struct cmdarg *cmdarg)
{
    struct poclidek_ctx   *cctx = NULL;
    tn_array               *pkgs = NULL;
    tn_array               *matched_pkgs = NULL;
    int                    i, err = 0, display_bar = 0, bar_v;
    int                    term_height;
    struct pattern         *pt;
    unsigned               flags;
    
    if ((pt = cmdarg->d) == NULL) {
        logn(LOGERR, _("search: no pattern given"));
        err++;
        goto l_end;
    }
    cmdarg->d = NULL;            /* we'll free pattern myself */

    cctx = cmdarg->cctx;
    
    flags = cmdarg->flags;
    flags &= ~OPT_NO_SEARCHSW;
    if (flags == 0)
        cmdarg->flags |= OPT_SEARCH_DEFAULT;
    
    init_pcre();
    if (!pattern_compile(pt, poldek_ts_get_arg_count(cmdarg->ts))) {
        err++;
        goto l_end;
    }
    
    if (poldek_ts_get_arg_count(cmdarg->ts) == 0) {
        pkgs = poclidek_get_current_pkgs(cctx);
        
    } else {
        pkgs = poclidek_resolve_packages(cctx, cmdarg->ts, 0);
    }
    
    if (pkgs == NULL)
        return 0;
    
    matched_pkgs = n_array_new(32, NULL, NULL);

    if (n_array_size(pkgs) > 5 && (cmdarg->flags & OPT_SEARCH_HDD)) {
        display_bar = 1;
        msg(0, _("Searching packages..."));
    }
    bar_v = 0;
    
    for (i=0; i < n_array_size(pkgs); i++) {
        struct pkg *pkg = n_array_nth(pkgs, i);
        
        if (pkg_match(pkg, pt, cmdarg->flags)) 
            n_array_push(matched_pkgs, pkg);
        
        if (display_bar) {
            int v, j;
            
            v = i * 40 / n_array_size(pkgs);
            for (j = bar_v; j < v; j++)
                msg(0, "_.");
            bar_v = v;
        }
        
        if (sigint_reached()) {
            msgn(0, _("_interrupted."));
            goto l_end;
        }
    }
    
    if (display_bar) 
        msgn(0, _("_done."));

    term_height = term_get_height();
    if (n_array_size(matched_pkgs) == 0) 
        printf_c(PRCOLOR_YELLOW, "No package matches '%s'\n", pt->regexp);
    
    else if (n_array_size(matched_pkgs) < term_height)
        printf_c(PRCOLOR_YELLOW, "%d package(s) found:\n",
                 n_array_size(matched_pkgs));
    
        
    for (i=0; i<n_array_size(matched_pkgs); i++) {
        struct pkg *pkg;

        pkg = n_array_nth(matched_pkgs, i);
        printf("%s\n", pkg->nvr);
    }

    if (n_array_size(matched_pkgs) >= term_height)
        printf_c(PRCOLOR_YELLOW, "%d package(s) found.\n",
                 n_array_size(matched_pkgs));
        
 l_end:

    if (pkgs)
        n_array_free(pkgs);
    
    if (matched_pkgs)
        n_array_free(matched_pkgs);
    
    if (cmdarg->d)
        cmdarg->d = NULL;

    pattern_free(pt);
    return 1;
}
