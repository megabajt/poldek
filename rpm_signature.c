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

#include <rpm/rpmlib.h>
#include <rpm/rpmio.h>
#include <rpm/rpmurl.h>
#include <rpm/rpmmacro.h>
#include <trurl/nassert.h>
#include <trurl/narray.h>
#include <trurl/nstr.h>

#ifdef HAVE_RPM_4_1
# include <rpm/rpmts.h>
# include <rpm/rpmps.h>
# include <rpm/rpmdb.h>
# include <rpm/rpmcli.h>
#endif

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

/* rpmlib's rpmCheckSig reports success when GPG signature is missing,
   so it is useless for real sig verification */
#if !defined HAVE_RPM_4_0
static int rpm_signatures(const char *path, unsigned *signature_flags, FD_t *fd)
{
    *signature_flags = POLDEK_VRFY_DGST;
    path = path;
    return 1;
}

#else 
static int rpm_signatures(const char *path, unsigned *signature_flags, FD_t *fd) 
{
    unsigned        flags;
    FD_t            fdt;
    struct rpmlead  lead;
    Header          sign = NULL;
    int32_t         tag, type, cnt;
    const void      *ptr;
    HeaderIterator  it;

    *signature_flags = 0;
    
    fdt = Fopen(path, "r.fdio");
    if (fdt == NULL || Ferror(fdt)) {
//        logn("open %s: %s", path, Fstrerror(fdt));
        if (fdt)
            Fclose(fdt);
        return 0;
    }

    if (readLead(fdt, &lead)) {
        logn(LOGERR, "%s: read package lead failed", path);
        Fclose(fdt);
        return 0;
    }
    
    if (rpmReadSignature(fdt, &sign, lead.signature_type) != 0) {
        logn(LOGERR, "%s: read package signature failed", path);
        Fclose(fdt);
        return 0;
    }
    
    if (sign == NULL) {
        logn(LOGERR, "%s: no signatures available", path);
        Fclose(fdt);
        return 0;
    }

    if (fd) {
        Fseek(fdt, 0, SEEK_SET);
        *fd = fdt;              /* fd to the caller */
        
    } else {
        Fclose(fdt);
    }
    

    flags = 0;
    it = headerInitIterator(sign);
    
    while (headerNextIterator(it, &tag, &type, &ptr, &cnt)) {
        switch (tag) {
#ifdef HAVE_RPM_4_1
            case RPMSIGTAG_RSA:
#endif                
	    case RPMSIGTAG_PGP5:	/* XXX legacy */
	    case RPMSIGTAG_PGP:
		flags |= POLDEK_VRFY_SIGNPGP;
		break;

#ifdef HAVE_RPM_4_1
            case RPMSIGTAG_DSA:
#endif                
	    case RPMSIGTAG_GPG:
		flags |= POLDEK_VRFY_SIGNGPG;
                break;
                
	    case RPMSIGTAG_LEMD5_2:
	    case RPMSIGTAG_LEMD5_1:
	    case RPMSIGTAG_MD5:
		flags |= POLDEK_VRFY_DGST;
		break;
                
	    default:
		continue;
		break;
        }
        ptr = headerFreeData(ptr, type);
    }

    headerFreeIterator(it);
    rpmFreeSignature(sign);
    *signature_flags = flags;
    return 1;
}
#endif 




#ifdef HAVE_RPMCHECKSIG         /* 4.0.x series */

#ifdef HAVE_RPM_4_1
# error "dupa"
#endif
int rpm_verify_signature(const char *path, unsigned flags) 
{
    const char *argv[2];
    unsigned presented_signs;

    n_assert(flags & (CHECKSIG_MD5 | CHECKSIG_GPG | CHECKSIG_PGP));

    if ((flags & (CHECKSIG_GPG | CHECKSIG_PGP))) {
        presented_signs = 0;
        
        if (!rpm_signatures(path, &presented_signs, NULL)) {
            logn(LOGERR, "dupa\n");
            return 0;
        }
        	
        
        if ((presented_signs & flags) == 0) {
            char signam[255];
            int n = 0;
            
            if (flags & CHECKSIG_MD5)
                n += n_snprintf(&signam[n], sizeof(signam) - n, "md5/");
            
            if (flags & CHECKSIG_GPG)
                n += n_snprintf(&signam[n], sizeof(signam) - n, "gpg/");
            
            if (flags & CHECKSIG_PGP)
                n += n_snprintf(&signam[n], sizeof(signam) - n, "pgp/");
            
            n_assert(n > 0);
            signam[n - 1] = '\0';   /* eat last '/' */
            logn(LOGWARN, _("%s: %s signature not found"), n_basenam(path),
                 signam);
            return 0;
        }
    }
    	
    

    argv[0] = path;
    argv[1] = NULL;

    return rpmCheckSig(flags, argv) == 0;
}

#else

int rpm_verify_signature(const char *path, unsigned flags) 
{
    const char                *argv[2];
    unsigned                  presented_signs = 0;
    struct rpmQVKArguments_s  qva; /* poor RPM API... */
    rpmts                     ts;
    FD_t                      fdt = NULL;
    int                       rc;
#ifdef HAVE_RPM_4_1
    static int                warn_printed  = 0;
#endif    

    n_assert(flags & (POLDEK_VRFY_DGST |
                      POLDEK_VRFY_SIGNGPG | POLDEK_VRFY_SIGNPGP));

#ifdef HAVE_RPM_4_1
    if (!warn_printed && (flags & (POLDEK_VRFY_SIGNGPG | POLDEK_VRFY_SIGNPGP))) {
        logn(LOGWARN, "Package signature verification for rpm 4.1 "
             "not implemented yet");
        warn_printed = 1;
    }
    return 1;
#endif
    
    if (!rpm_signatures(path, &presented_signs, NULL))
        return 0;
    
    if ((presented_signs & flags) == 0) {
        char signam[255];
        int n = 0;
            
        if (flags & POLDEK_VRFY_DGST)
            n += n_snprintf(&signam[n], sizeof(signam) - n, "digest/");
            
        if (flags & POLDEK_VRFY_SIGNGPG)
            n += n_snprintf(&signam[n], sizeof(signam) - n, "gpg/");
            
        if (flags & POLDEK_VRFY_SIGNPGP)
            n += n_snprintf(&signam[n], sizeof(signam) - n, "pgp/");
            
        n_assert(n > 0);
        signam[n - 1] = '\0';   /* eat last '/' */
        logn(LOGWARN, _("%s: %s signature not found"), n_basenam(path),
             signam);
        return 0;
    }
    
    memset(&qva, '\0', sizeof(qva));
    qva.qva_flags = flags;
    ts = rpmtsCreate();

    fdt = Fopen(path, "r.ufdio");
    printf("rpmVerifySignatures %p %p %p %s\n", &qva, ts, fdt, path);
    rc = (rpmVerifySignatures(&qva, ts, fdt, n_basenam(path)) == 0);

    rpmtsFree(ts);
    Fclose(fdt);
    return rc == 0;
}

#endif
