/* 
  Copyright (C) 2000 - 2002 Pawel A. Gajda (mis@k2.net.pl)

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as published
  by the Free Software Foundation;
 
  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  59 Place - Suite 330, Boston, MA 02111-1307, USA.  
*/

/* $Id$ */

#ifndef POLDEK_VFILE_H
#define POLDEK_VFILE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <zlib.h>
#include <trurl/narray.h>

#ifdef ENABLE_VFILE_TRURLIO
# include <trurl/nstream.h>
#endif

extern int *vfile_verbose;
extern const char *vfile_anonftp_passwd;
extern void (*vfile_msg_fn)(const char *fmt, ...);
extern void (*vfile_msgtty_fn)(const char *fmt, ...);
extern void (*vfile_err_fn)(const char *fmt, ...);

void vfile_init(void);

#define VFILE_CONF_CACHEDIR                     0
#define VFILE_CONF_DEFAULT_CLIENT               1
#define VFILE_CONF_SYSUSER_AS_ANONPASSWD        2
#define VFILE_CONF_VERBOSE                      3
#define VFILE_CONF_PROXY                        4

int vfile_configure(int param, ...);

struct vfile_url {
    char *url;
    char label[128];
};


#define VFT_IO       1             /* open(2)                   */
#define VFT_STDIO    2             /* fopen(3)                  */
#define VFT_GZIO     3             /* zlib: gzopen()            */ 
#define VFT_RPMIO    4             /* rpmlib: Fopen()           */
#define VFT_TRURLIO  5             /* trurlib's tn_stream       */

#define VFM_RO         (1 << 0)  /* RO, this is the default   */
#define VFM_RW         (1 << 1)
#define VFM_APPEND     (1 << 3)  /* a+ */

#define VFM_NORM       (1 << 4)  /* (NoReMove) for remote files,
                                    remove tmp at close? */

#define VFM_CACHE      (1 << 5)  /* for remote files, use cached
                                                 file if it exists */

#define VFM_CACHE_ONLY (1 << 6)  /* for remote files, use cached file
                                    if it not exists return NULL */

#define VFM_STBRN      (1 << 10)  /* infinite retrying to open file  */


#define VFM_NOEMPTY    (1 << 11)  /* treat empty files as non-existing ones */

#define VFM_UNCOMPR    (1 << 12)  /* uncompress file before open  */

/* flags  */
#define VF_FETCHED     (1 << 15) /* for remote files, file downloaded */
#define VF_FRMCACHE    (1 << 16) /* file remote file, file taken form cache */

struct vfile {
    int       vf_type;                /* VFT_*   */
    unsigned  vf_urltype;             /* VFURL_* */
    unsigned  vf_mode;                /* VFM_*   */
    unsigned  vf_flags;               /* VF_*    */ 
    union {
        int        vfile_fd;
        FILE       *vfile_stream;
        gzFile     *vfile_gzstream;
        void       *vfile_fdt;        /* RPM's FD_t */
#ifdef ENABLE_VFILE_TRURLIO        
        tn_stream  *vfile_tnstream;
#endif        
    } vfile_fdescriptor;

    char          *vf_path;
    char          *vf_tmpath;
    int16_t       _refcnt;
};

#define	vf_fd        vfile_fdescriptor.vfile_fd
#define	vf_stream    vfile_fdescriptor.vfile_stream
#define	vf_gzstream  vfile_fdescriptor.vfile_gzstream
#define	vf_fdt       vfile_fdescriptor.vfile_fdt
#ifdef ENABLE_VFILE_TRURLIO
# define	vf_tnstream  vfile_fdescriptor.vfile_tnstream
#endif

#define vfile_localpath(vf)  ((vf)->vf_tmpath ? (vf)->vf_tmpath : (vf)->vf_path)

struct vfile *vfile_open(const char *path, int vftype, unsigned vfmode);
void vfile_close(struct vfile *vf);
struct vfile *vfile_incref(struct vfile *vf);

int vfile_unlink(struct vfile *vf);


#define VFURL_UNKNOWN (1 << 0)
#define VFURL_PATH    (1 << 1)
#define VFURL_FTP     (1 << 2)
#define VFURL_HTTP    (1 << 3)
#define VFURL_HTTPS   (1 << 4)
#define VFURL_RSYNC   (1 << 5)
#define VFURL_CDROM   (1 << 6)

#define VFURL_LOCAL    (VFURL_CDROM | VFURL_PATH)
#define VFURL_REMOTE   ~(VFURL_LOCAL)


#define vfile_is_remote(vf) ((vf)->vf_urltype & VFURL_REMOTE)

/* external fetchers */
int vfile_register_ext_handler(const char *name, tn_array *protocols,
                               const char *cmd);
int vfile_is_configured_ext_handler(const char *url);


int vfile_fetch_ext(const char *destdir, const char *url);
int vfile_fetcha_ext(const char *destdir, tn_array *urls);


int vfile_fetch(const char *destdir, const char *url);
int vfile_fetcha(const char *destdir, tn_array *urls);


int vf_url_type(const char *url);
char *vf_url_proto(char *proto, int size, const char *url);
int vf_url_as_dirpath(char *buf, size_t size, const char *url);
int vf_url_as_path(char *buf, size_t size, const char *url);

/* replace password with "x" * len(password) */
const char *vf_url_hidepasswd(char *buf, int size, const char *url);
const char *vf_url_hidepasswd_s(const char *url);

/* applies vf_url_hidepasswd() + slim down url string to maxl */
const char *vf_url_slim(char *buf, int size, const char *url, int maxl);
const char *vf_url_slim_s(const char *url, int maxl);

int vf_valid_path(const char *path);
int vf_mkdir(const char *path);
int vf_unlink(const char *path);

/* mkdir under cachedir */
int vf_mksubdir(char *path, int size, const char *dirpath);

/* url to local path */
int vf_localpath(char *path, size_t size, const char *url);
int vf_localdirpath(char *path, size_t size, const char *url);

/* unlink local copy */
int vf_localunlink(const char *path);

int vf_userathost(char *buf, int size);
int vf_cleanpath(char *buf, int size, const char *path);


#ifdef VFILE_INTERNAL

#include <trurl/n_snprintf.h>
#include <trurl/nhash.h>

struct vfile_configuration {
    char      *cachedir;
    unsigned  flags;
    unsigned  mod_fetch_flags;   /* passed to mod->fetch() */

    tn_hash   *default_clients_ht;
    tn_hash   *proxies_ht;
    int       *verbose;
};

extern struct vfile_configuration vfile_conf;

void vfile_set_errno(const char *ctxname, int vf_errno);

#include "vfreq.h"

struct vf_module {
    char       vfmod_name[32];
    unsigned   vf_protocols;
    
    int        (*init)(void);
    void       (*destroy)(void);
    int        (*fetch)(struct vf_request *req);
    int        _pri;            /* used by vfile only */
};


#define VFMOD_INFINITE_RETR       (1 << 0) /* retry download */
#define VFMOD_USER_AS_ANONPASSWD  (1 << 1) /* send login@host as FTP password  */

/* short alias for */
#define CL_URL(url) vf_url_hidepasswd_s(url)
#define PR_URL(url) vf_url_slim_s(url, 60)

int vf_uncompr_able(const char *path);
int vf_uncompr_do(const char *path, const char *destpath);

void vf_sigint_cb(void);

#endif /* VFILE_INTERNAL */

#endif /* POLDEK_VFILE_H */

