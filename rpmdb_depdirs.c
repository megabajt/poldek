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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_DB_185_H 
# include <db_185.h>
#endif

#include <rpm/rpmlib.h>
#include <rpm/rpmio.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmmacro.h>
#include <trurl/nassert.h>
#include <trurl/narray.h>
#include <trurl/nstr.h>

#include <vfile/vfile.h>

#include "i18n.h"
#include "rpm.h"
#include "rpmadds.h"
#include "depdirs.h"
#include "misc.h"
#include "log.h"
#include "pkg.h"
#include "dbpkg.h"
#include "capreq.h"
#include "rpmdb_it.h"


/*
  open req index directly, rpmlib API does not allow to extract
  all requirements without reading whole headers (which is too slow)
*/
#ifndef HAVE_DB_185_H
int rpmdb_get_depdirs(const char *rootdir, tn_array *depdirs)
{
    rootdir = rootdir; depdirs = depdirs;
    return -1;
}

#else 
int rpmdb_get_depdirs(const char *rootdir, tn_array *depdirs) 
{
    DB        *db;
    DBT       dbt_k, dbt_d;
    char      buf[PATH_MAX], path[PATH_MAX], *depdir;
    char      *index, *p, *dbpath;
    tn_array  *tmp_depdirs;
    int       len;

#ifndef HAVE___DB185_OPEN
    return -1;
#endif    
    
    index = "requirename.rpm";
#ifdef HAVE_RPM_4_0
    index = "Requirename";
#endif
    
    if (rootdir == NULL)
        rootdir = "/";
    dbpath = rpm_get_dbpath();
    snprintf(path, sizeof(path), "%s%s/%s", *(rootdir + 1) == '\0' ? "" : rootdir,
             dbpath != NULL ? dbpath : "", index);
    
    if ((db = __db185_open(path, O_RDONLY, 0, DB_HASH, NULL)) == NULL)
        return -1;
    
    if (db->seq(db, &dbt_k, &dbt_d, R_FIRST) != 0) {
        db->close(db);
        return -1;
    }
    
    tmp_depdirs = n_array_new(128, NULL, (tn_fn_cmp)strcmp);
    
    if (dbt_k.size > 0 && *(char*)dbt_k.data == '/' && dbt_k.size < sizeof(buf)) {
        memcpy(buf, dbt_k.data, dbt_k.size);
        buf[dbt_k.size] = '\0';
        DBGF("ldbreq %s\n", buf);
        depdir = path2depdir(buf);
        len = strlen(depdir);
        p = alloca(len + 1);
        memcpy(p, depdir, len + 1);
        n_array_push(tmp_depdirs, p);
    }
            
    while (db->seq(db, &dbt_k, &dbt_d, R_NEXT) == 0) {
        if (dbt_k.size > 0 && *(char*)dbt_k.data == '/' && dbt_k.size < sizeof(buf)) {
            memcpy(buf, dbt_k.data, dbt_k.size);
            buf[dbt_k.size] = '\0';
            DBGF("ldbreq %s\n", buf);
            depdir = path2depdir(buf);
            len = strlen(depdir);
            p = alloca(len + 1);
            memcpy(p, depdir, len + 1);
            n_array_push(tmp_depdirs, p);
        }
    }
    db->close(db);
    

    n_array_sort(tmp_depdirs);
    n_array_uniq(tmp_depdirs);
    
    while (n_array_size(tmp_depdirs)) {
        char *dir = n_array_shift(tmp_depdirs);
        
        if (n_array_bsearch(depdirs, dir) == NULL) {
            //printf("dir = %s\n", dir);
            n_array_push(depdirs, n_strdup(dir));
            n_array_isort(depdirs);
        }
    }
    n_array_free(tmp_depdirs);
    //printf("s = %d\n", n_array_size(depdirs));
    return n_array_size(depdirs);
}
#endif /* HAVE_DB_185_H */
