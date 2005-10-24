#ifndef POLDEK_PM_RPM_MODULE_H
#define POLDEK_PM_RPM_MODULE_H

#include <rpm/rpmlib.h>
#ifdef HAVE_RPM_4_0_4
# include <rpm/rpmcli.h>
#endif

#ifdef HAVE_RPM_4_1
# include <rpm/rpmts.h>
#endif

#include <trurl/trurl.h>
#include "poldek.h"
#include "pm/pm.h"

#define PM_RPM_CMDSETUP_DONE (1 << 0)
struct pm_rpm {
    unsigned flags;
    char *rpm;
    char *sudo;
    char *default_dbpath;
};

void *pm_rpm_init(void);
void pm_rpm_destroy(void *pm_rpm);
int pm_rpm_configure(void *modh, const char *key, void *val);
tn_array *pm_rpm_rpmlib_caps(void *pm_rpm);
const char *pm_rpm_get_arch(void *pm_rpm);

char *pm_rpm_dbpath(void *pm_rpm, char *path, size_t size);
time_t pm_rpm_dbmtime(void *pm_rpm, const char *dbfull_path);
int pm_rpm_dbdepdirs(void *pm_rpm, const char *rootdir, const char *dbpath, 
                     tn_array *depdirs);

int pm_rpm_packages_install(struct pkgdb *db,
                            tn_array *pkgs, tn_array *pkgs_toremove,
                            struct poldek_ts *ts);
int pm_rpm_packages_uninstall(struct pkgdb *db,
                              tn_array *pkgs, struct poldek_ts *ts);

#ifdef HAVE_RPM_4_1
# include <rpm/rpmcli.h>
# define VRFYSIG_DGST     VERIFY_DIGEST
# define VRFYSIG_SIGN     VERIFY_SIGNATURE
# define VRFYSIG_SIGNGPG  VERIFY_SIGNATURE
# define VRFYSIG_SIGNPGP  VERIFY_SIGNATURE
#else
# define VRFYSIG_DGST     CHECKSIG_MD5
# define VRFYSIG_SIGN     CHECKSIG_GPG
# define VRFYSIG_SIGNGPG  CHECKSIG_GPG
# define VRFYSIG_SIGNPGP  CHECKSIG_PGP
#endif

int pm_rpm_verify_signature(void *pm_rpm, const char *path, unsigned flags);


rpmdb pm_rpm_opendb(void *pm_rpm, void *dbh, 
                    const char *dbpath, const char *rootdir, mode_t mode,
                    tn_hash *kw);
void pm_rpm_closedb(rpmdb db);


int pm_rpm_db_it_init(struct pkgdb_it *it, int tag, const char *arg);
int pm_rpm_install_package(struct pkgdb *db, const char *path,
                           const struct poldek_ts *ts);

int pm_rpm_vercmp(const char *one, const char *two);

/************/
/*  rpmhdr  */
int pm_rpmhdr_loadfdt(FD_t fdt, Header *hdr, const char *path);
int pm_rpmhdr_loadfile(const char *path, Header *hdr);
int pm_rpmhdr_nevr(void *h, char **name,
                   int32_t *epoch, char **version, char **release,
                   char **arch, int *color);

char **pm_rpmhdr_langs(Header h);
int pm_rpmhdr_get_raw_entry(Header h, int32_t tag, void *buf, int32_t *cnt);
void pm_rpmhdr_free_entry(void *e, int type);

int pm_rpmhdr_issource(Header h);

void *pm_rpmhdr_link(void *h);
void pm_rpmhdr_free(void *h);

char *pm_rpmhdr_snprintf(char *buf, size_t size, Header h);

struct rpmhdr_ent {
    int32_t tag;
    int32_t type;
    void *val;
    int32_t cnt;
};

#define pm_rpmhdr_ent_as_int32(ent) (*(int32_t*)(ent)->val)
#define pm_rpmhdr_ent_as_int16(ent) (*(int16_t*)(ent)->val)
#define pm_rpmhdr_ent_as_str(ent) (char*)(ent)->val
#define pm_rpmhdr_ent_as_strarr(ent) (char**)(ent)->val

int pm_rpmhdr_ent_get(struct rpmhdr_ent *ent, Header h, int32_t tag);
void pm_rpmhdr_ent_free(struct rpmhdr_ent *ent);
int pm_rpmhdr_ent_cp(struct rpmhdr_ent *ent, Header h, int32_t tag, Header toh);



struct pkg *pm_rpm_ldhdr(tn_alloc *na, Header h,
                         const char *fname, unsigned fsize,
                         unsigned ldflags);

struct pkg *pm_rpm_ldpkg(void *pm_rpm,
                         tn_alloc *na, const char *path, unsigned ldflags);

int pm_rpm_ldhdr_fl(tn_alloc *na, tn_tuple **fl,
                    Header h, int which, const char *pkgname);

tn_array *pm_rpm_ldhdr_capreqs(tn_array *arr, const Header h, int crtype);
int pm_rpm_machine_score(void *pm_rpm, int tag, const char *val);

struct pkgdir;
struct pkgdir *pm_rpm_db_to_pkgdir(void *pm_rpm, const char *rootdir,
                                   const char *dbpath, tn_hash *kw);

int pm_rpm_arch_score(const char *arch);
int pm_rpm_vercmp(const char *one, const char *two);


void pm_rpm_setup_commands(struct pm_rpm *pm);

#endif
