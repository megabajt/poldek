/*
  Copyright (C) 2000 - 2002 Pawel A. Gajda <mis@k2.net.pl>

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

#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <trurl/nmalloc.h>
#include <trurl/nassert.h>
#include <trurl/nstr.h>
#include <trurl/n_snprintf.h>

#include <vfile/vfile.h>

#include "pkgdir.h"
#include "source.h"
#include "misc.h"
#include "log.h"
#include "poldek_term.h"
#include "i18n.h"

#define SOURCE_DEFAULT_PRI 0

struct subopt {
    char      *name;
    unsigned  flag;              /* MUST BE non-zero */
    int       isdefault;         /* is default value */
};

struct src_option {
    char      *name;
    int       len;
    unsigned  flag;
    struct subopt *subopts;
};

#define PKGSRC_OPTION_SUBOPT  (1 << 15)

static struct subopt type_subopts[] = {
    { "pidx",    PKGSRCT_IDX, 1 }, 
    { "dir",     PKGSRCT_DIR, 0 }, 
    { "hdrl",    PKGSRCT_HDL, 0 },
    { NULL, 0, 0 },
};

static struct src_option source_options[] = {
    { "noauto",   0, PKGSOURCE_NOAUTO,      NULL}, 
    { "noautoup", 0, PKGSOURCE_NOAUTOUP,    NULL}, 
    { "gpg",      0, PKGSOURCE_VRFY_GPG,    NULL},
    { "pgp",      0, PKGSOURCE_VRFY_PGP,    NULL},
    { "sign",     0, PKGSOURCE_VRFY_SIGN,   NULL},
    { "type",     0, PKGSOURCE_TYPE | PKGSRC_OPTION_SUBOPT, type_subopts },
    { "pri",      0, PKGSOURCE_PRI | PKGSRC_OPTION_SUBOPT, NULL},
    {  NULL,      0, 0, NULL }, 
};

    
static unsigned find_subopt(const char *optstr, struct subopt *subopts)
{
    int i;
    unsigned flag = 0;
    
    i = 0;
    while (subopts[i].name) {
        if (strcmp(subopts[i].name, optstr) == 0) {
            flag = subopts[i].flag;
            break;
        }
        i++;
    }

    return flag;
}

static
unsigned get_subopt(struct source *src, struct src_option *opt,
                    const char *str, const char *options_str)
{
    unsigned v = 0;
    
    n_assert(strncmp(str, opt->name, opt->len) == 0);
    
    str += opt->len;
    if (*str != '=') {
        logn(LOGWARN, _("%s: %s unknown option"), options_str, str);
        return 0;
    }
    
    str++;
    
    if (opt->flag & PKGSOURCE_TYPE) {
        if ((v = find_subopt(str, opt->subopts))) {
            src->type = v;
            src->subopt_flags |= v;
        }
        
    } else if (opt->flag & PKGSOURCE_PRI) {
        if (sscanf(str, "%d", &v) == 1)
            src->pri = v;
    }

    if (v == 0)
        logn(LOGWARN, _("%s%sinvalid value ('%s') for option '%s'"),
             src->name ? src->name : "", src->name ? ": " : "", 
             str, opt->name);

    return v;
}


struct source *source_new(const char *pathspec, const char *pkg_prefix)
{
    struct source   *src;
    struct stat     st;
    const char      *path, *p;
    char            *name, *q;
    int             len;
    char            clpath[PATH_MAX], clprefix[PATH_MAX];
    int             n;
    unsigned        flags = 0;
    
    p = pathspec;
    
    while (*p && *p != '|' && !isspace(*p))
        p++;

    if (*p == '\0') {           /* path only */
        path = pathspec;
        name = "-";
        
    } else {
        path = p + 1;
        while (isspace(*path))
            path++;
        
        len = p - pathspec;
        name = alloca(len + 1);
        memcpy(name, pathspec, len);
        name[len] = '\0';
        
        if (*name == '[') 
            name++;
        
        if ((q = strrchr(name, ']')))
            *q = '\0';
        
        if (*name == '\0')
            name = "-";
        else
            flags = PKGSOURCE_ISNAMED;
    }


    if ((n = vf_cleanpath(clpath, sizeof(clpath), path)) == 0 ||
        n == sizeof(clpath))
        return NULL;
    
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode))
        clpath[n++] = '/';
    
    else {
        int l = strlen(path);
        if (path[l - 1] == '/')
            clpath[n++] = '/';
    }
    clpath[n] = '\0';

    if (pkg_prefix) {
        if ((n = vf_cleanpath(clprefix, sizeof(clprefix), pkg_prefix)) == 0 ||
            n == sizeof(clprefix))
            return NULL;
    }
    
    src = n_malloc(sizeof(*src));
    src->flags = src->subopt_flags = 0;
    src->path = n_strdup(clpath);
    if (pkg_prefix)
        src->pkg_prefix = n_strdup(clprefix);
    else
        src->pkg_prefix = NULL;
    src->type = PKGSRCT_NIL;
    src->pri = 0;
    
    if ((q = strchr(name, ','))) {
        const char **tl, **t;
        
        *q++ = '\0';
        src->name = name;       /* temporary */
        
        tl = t = n_str_tokl(q, ",");
        n_assert(tl);

        while (*t) {
            int n = 0;
            while (source_options[n].name != NULL) {
                struct src_option *opt = &source_options[n];
                
                if (opt->len == 0)
                    opt->len = strlen(opt->name);
                
                if (opt->flag & PKGSRC_OPTION_SUBOPT) {
                    if (strncmp(*t, opt->name, opt->len) == 0) {
                        if (get_subopt(src, opt, *t, name))
                            src->flags |= opt->flag;
                        break;
                    }
                    
                } else if (strcmp(*t, opt->name) == 0) {
                    src->flags |= opt->flag;
                    break;
                }
                
                n++;
            }
            
            if (source_options[n].name == NULL)
                logn(LOGWARN, _("%s: %s unknown option"), name, *t);
            t++;
        }
        n_str_tokl_free(tl);
    }

    src->name = n_strdup(name);
    src->flags |= flags;
    
    if (src->type == PKGSRCT_HDL) /* not updateable type */
        src->flags |= PKGSOURCE_NOAUTOUP;
    return src;
}

void source_free(struct source *src)
{
    free(src->path);
    if (src->pkg_prefix)
        free(src->pkg_prefix);
    if (src->name)
        free(src->name);
    free(src);
}


int source_cmp(struct source *s1, struct source *s2)
{
    return strcmp(s1->path, s2->path);
}


int source_cmp_pri(struct source *s1, struct source *s2)
{
    return s1->pri - s2->pri;
}


int source_cmp_name(struct source *s1, struct source *s2)
{
    if (strcmp(s1->name, "-") == 0)
        return 1;

    if (strcmp(s2->name, "-") == 0)
        return -1;
    
    return strcmp(s1->name, s2->name);
}


int source_cmp_pri_name(struct source *s1, struct source *s2)
{
    int rc;
    
    if ((rc = (s1->pri - s2->pri)) == 0)
        return source_cmp_name(s1, s2);
    
    return rc;
}


static int source_update_a(struct source *src) 
{
    int nerr = 0;
    
    switch (src->type) {
        case PKGSRCT_NIL:
        case PKGSRCT_IDX:
            if (!update_whole_pkgdir(src->path))
                nerr++;
            break;

        case PKGSRCT_HDL: {
            struct vfile *vf;
                
            unlink_pkgdir_files(src->path, 0);
            if ((vf = vfile_open(src->path, VFT_IO, VFM_RO | VFM_NORM)) == NULL)
                nerr++;
            else
                vfile_close(vf);
        }
        break;

        case PKGSRCT_DIR:
            break;

        default:
            n_assert(0);
            break;
    }
        
    return nerr == 0;
}

static int source_update_pidx(struct source *src) 
{
    struct pkgdir  *pkgdir;
    int            nerr = 0;


    pkgdir = pkgdir_new(src->name, src->path,
                        src->pkg_prefix, PKGDIR_NEW_VERIFY);

    if (pkgdir == NULL) {
        if (!source_is_remote(src))
            return 0;
        
        logn(LOGNOTICE, _("%s: load of local index failed, "
                          "getting whole index..."),
             source_idstr(src));
        
        unlink_pkgdir_files(src->path, 0);
        if (!source_update_a(src))
            nerr++;
        
    } else {
        if ((pkgdir->vf->vf_flags & VF_FETCHED) == 0) { /* not already downloaded */
            int npatches = 0;
            
            if (!pkgdir_update(pkgdir, &npatches))
                nerr++;
            else if (npatches)
                if (!pkgdir_create_idx(pkgdir, NULL, 0))
                    nerr++;
        }
        
        pkgdir_free(pkgdir);
    }
    
    return nerr == 0;
}


int source_update(struct source *src, unsigned flags)
{
    int            nerr = 0;

    if (flags & PKGSOURCE_UPA)
        return source_update_a(src);
    
    switch (src->type) {
        case PKGSRCT_NIL:
        case PKGSRCT_IDX:
            if (!source_update_pidx(src)) 
                nerr++;
            break;
        
        case PKGSRCT_HDL: 
            logn(LOGWARN, _("%s: this type of source is not updateable; "
                            "use --upa to refresh it"),
                 source_idstr(src));
            nerr++;
            break;

        case PKGSRCT_DIR:
            logn(LOGWARN, _("%s: this type of source is not updateable"), 
                 source_idstr(src));
            nerr++;
            break;

        default:
            n_assert(0);
            break;
    }

    return nerr == 0;
}


static
int source_snprintf_flags(char *str, int size, const struct source *src)
{
    int n, i;
    
    n_assert(size > 0);
    
    *str = '\0';

    i = n = 0;
    while (source_options[i].name != NULL) {
        struct src_option *opt = &source_options[i++];
        
        if (opt->len == 0)
            opt->len = strlen(opt->name);

        if ((src->flags & opt->flag) == 0)
            continue;

        if ((opt->flag & PKGSRC_OPTION_SUBOPT) == 0) {
            n += snprintf_c(PRCOLOR_GREEN, &str[n], size - n, "%s", opt->name);
            n += n_snprintf(&str[n], size - n, ",");
            // n += n_snprintf(&str[n], size - n, "%s,", opt->name);

        } else if (opt->flag & PKGSOURCE_PRI) {
            if (src->pri) {
                n += snprintf_c(PRCOLOR_GREEN, &str[n], size - n, "%s", opt->name);
                n += n_snprintf(&str[n], size - n, "=%d,", src->pri);
            }
            
        } else {
            int j = 0;
            
            while (opt->subopts[j].name != NULL) {
                struct subopt *subopt = &opt->subopts[j++];
                
                if (subopt->isdefault)
                    continue;
                    
                if (src->subopt_flags & subopt->flag) {
                    n += snprintf_c(PRCOLOR_GREEN, &str[n], size - n, "%s",
                                    opt->name);
                    
                    n += n_snprintf(&str[n], size - n, "=%s,", subopt->name);
                    
                    //n += n_snprintf(&str[n], size - n, "%s=%s,", opt->name,
                    //                subopt->name);
                    break;
                }
            }
        }
    }
    
    
    if (n > 0)
        str[n - 1] = '\0';      /* eat last comma */
    
    return n;
}


void source_printf(const struct source *src) 
{
    char optstr[256];
    
    source_snprintf_flags(optstr, sizeof(optstr), src);
    
    printf("%-12s %s%s%s%s\n",
           src->name, vf_url_slim_s(src->path, 0),
           *optstr ? "  (" : "", optstr, *optstr ? ")" : "");

    if (src->pkg_prefix) {
        //printf_c(PRCOLOR_GREEN, "%-14s prefix: ", "");
        //printf("%s\n", src->pkg_prefix);
        printf("%-14s prefix => %s\n", "", vf_url_slim_s(src->pkg_prefix, 0));
    }
}

int sources_update(tn_array *sources, unsigned flags)
{
    int i, nerr = 0;
    
    for (i=0; i < n_array_size(sources); i++) {
        struct source *src = n_array_nth(sources, i);
        
        if (src->flags & PKGSOURCE_NOAUTOUP)
            continue;
        
        if (i > 0)
            msgn(0, "\n");

        if (!source_update(src, flags))
            nerr++;
    }

    return nerr == 0;
}

int sources_clean(tn_array *sources, unsigned flags) 
{
    int i,  nerr = 0;
    
    for (i=0; i < n_array_size(sources); i++) {
        struct source *src = n_array_nth(sources, i);
        
        if (!unlink_pkgdir_files(src->path, flags & PKGSOURCE_CLEANA))
            nerr++;
    }

    return nerr == 0;
}


int sources_add(tn_array *sources, struct source *src) 
{
    src->no = n_array_size(sources);
    n_array_push(sources, src);
    return n_array_size(sources);
}


void sources_score(tn_array *sources) 
{
    int i;
    int pri_min = INT_MAX;
    
    for (i=0; i < n_array_size(sources); i++) {
        struct source *src = n_array_nth(sources, i);
        if (src->pri < pri_min)
            pri_min = src->pri;
    }

    for (i=0; i < n_array_size(sources); i++) {
        struct source *src = n_array_nth(sources, i);
        if (src->pri == 0)
            src->pri = src->no + pri_min + 1;
    }
}
