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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <signal.h>
#include <time.h>
#include <argp.h>
#include <time.h>

#include <trurl/trurl.h>
#include <trurl/nobstack.h>

#include <sigint/sigint.h>
#include "i18n.h"
#include "misc.h"
#include "log.h"
#include "cli.h"
#include "cmd.h"
#include "cmd_pipe.h"
#include "arg_packages.h"


int shOnTTY = 0;

static volatile sig_atomic_t shInCmd  = 0;

static unsigned argp_parse_flags = ARGP_NO_EXIT;

static int argv_is_help(int argc, const char **argv);

extern struct poclidek_cmd command_ls;
extern struct poclidek_cmd command_install;
extern struct poclidek_cmd command_uninstall;
//extern struct poclidek_cmd command_get;
extern struct poclidek_cmd command_search;
extern struct poclidek_cmd command_desc;
extern struct poclidek_cmd command_cd;
extern struct poclidek_cmd command_pwd;
extern struct poclidek_cmd command_external;
extern struct poclidek_cmd command_help;

static struct poclidek_cmd *commands_tab[] = {
    &command_ls,
    &command_search,
    &command_desc,
    &command_install, 
    &command_uninstall,
    &command_cd,
    &command_pwd,
    &command_external,
    &command_help,
    NULL
};

struct sh_cmdctx {
    unsigned        cmdflags;
    int             err;
    struct cmdctx   *cmdctx;
    struct poclidek_cmd  *cmd;
    error_t (*parse_opt_fn)(int, char*, struct argp_state*);
};


/* default parse_opt */
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct sh_cmdctx *sh_cmdctx = state->input;
    unsigned flags = sh_cmdctx->cmdflags;
    int rc;


    state->input = sh_cmdctx->cmdctx;
    
    if (sh_cmdctx->parse_opt_fn)
        rc = sh_cmdctx->parse_opt_fn(key, arg, state);
    else
        rc = ARGP_ERR_UNKNOWN;
    state->input = sh_cmdctx;
    
    if (rc == EINVAL) 
        sh_cmdctx->err = 1;

    if (rc != ARGP_ERR_UNKNOWN)
        return rc;
    
    rc = 0;

    switch (key) {
        case 'v': {
            if ((flags & COMMAND_HASVERBOSE) == 0) {
                argp_usage (state);
                sh_cmdctx->err = 1;
                
            } else {
                verbose++;
            }
        }
        break;
        
            
        case ARGP_KEY_ARG:
            if (flags & COMMAND_NOARGS) {
                argp_usage (state);
                sh_cmdctx->err = 1; 
                return EINVAL;
            }
            //printf("push\n");
            poldek_ts_add_pkgmask(sh_cmdctx->cmdctx->ts, arg);
            break;
            
        case 'h':
            argp_state_help(state, stdout, ARGP_HELP_LONG | ARGP_HELP_DOC |
                            ARGP_HELP_USAGE);
            return EINVAL;
            break;
            
        case ARGP_KEY_NO_ARGS:
            if (sh_cmdctx->cmdctx->rtflags & CMDCTX_ISHELP)
                break;
            
            //printf("ARGP_KEY_NO_ARGS --\n");
            if ((flags & COMMAND_NOARGS) == 0 &&
                (flags & COMMAND_EMPTYARGS) == 0) {
                //printf("ARGP_KEY_NO_ARGS\n");
                argp_usage (state);
                sh_cmdctx->err = 1; 
                return EINVAL;
            }
            break;
            
            
        case ARGP_KEY_ERROR:
            //printf("ARGP_KEY_ERROR\n");
            sh_cmdctx->err = 1;
            return EINVAL;
            break;
            
        default:
            return ARGP_ERR_UNKNOWN;
    }
    
    //printf("key = %d, rc = %d\n", key, rc);
    return rc;
}

static char *help_filter(int key, const char *text, void *input) 
{
    struct sh_cmdctx *sh_cmdctx = input;

    if (key == ARGP_KEY_HELP_EXTRA) {
        char *p, buf[4096];
        int n = 0;
        
        
        if (sh_cmdctx->cmd->extra_help) 
            n += n_snprintf(&buf[n], sizeof(buf) - n, "  %s\n",
                          sh_cmdctx->cmd->extra_help);
        
#if 0
		alias.cmd = sh_cmdctx->cmd;

        if (n_array_bsearch_ex(cctx->aliases, &alias,
                               (tn_fn_cmp)command_alias_cmd_cmp)) {
           int i = 0;
		   struct poclidek_cmd_alias *alias;

            n += n_snprintf(&buf[n], sizeof(buf) - n, "%s",
                            _("  Defined aliases:\n"));
			
            while (i < n_array_size(cctx->aliases)) {
				alias = n_array_nth(cctx->aliases, i);
				if (alias->cmd == sh_cmdctx->cmd)
	                n += n_snprintf(&buf[n], sizeof(buf) - n,
                                    "    %-16s  \"%s\"\n",
                                    alias->name, alias->cmdline);
				i++;
            }
        }
#endif        
        if (n > 0) {
            p = n_malloc(n + 1);
            return memcpy(p, buf, n + 1);
        }
    }
    
    return (char*)text;
}

static
int do_exec_cmd_ent(struct cmdctx *cmdctx, int argc, char **argv) 
{
    struct sh_cmdctx     sh_cmdctx;
    int                  rc = 1, verbose_;
    unsigned             parse_flags;
    struct poclidek_cmd  *cmd;
    struct argp          argp = { cmdctx->cmd->argp_opts, parse_opt,
                                  cmdctx->cmd->arg,
                                  cmdctx->cmd->doc, 0, 0, 0};

    verbose_ = verbose;
    if (argv == NULL)
        return 0;

    cmd = cmdctx->cmd;
    if (argv_is_help(argc, (const char**)argv)) {
        cmdctx->rtflags |= CMDCTX_ISHELP;
        printf("is_help!\n");
    }
    
    
    cmdctx->_data = NULL;
    if (cmd->init_cmd_arg_d)
        cmdctx->_data = cmd->init_cmd_arg_d();

    if (cmd->cmd_fn) { /* option parses its args itself */
        printf("run cmd_fn(arc, argv)\n");
        rc = cmd->cmd_fn(cmdctx, argc, (const char**)argv, &argp);
        goto l_end;
    }
    
    
    if ((cmd->flags & COMMAND_NOHELP) && (cmd->flags & COMMAND_NOARGS) &&
        (cmd->flags & COMMAND_NOOPTS)) {
        printf("run do_cmd_fn, NOHELP, etc\n");
        rc = cmd->do_cmd_fn(cmdctx);
        goto l_end;
    }

    sh_cmdctx.cmdflags = cmd->flags; 
    sh_cmdctx.err = 0;
    sh_cmdctx.cmdctx = cmdctx;
    sh_cmdctx.cmd = cmd;
    sh_cmdctx.parse_opt_fn = cmd->parse_opt_fn;

    argp.help_filter = help_filter;
    parse_flags = argp_parse_flags;
    argp_parse(&argp, argc, (char**)argv, parse_flags, 0, (void*)&sh_cmdctx);

    if (sh_cmdctx.err) {
        rc = 0;
        goto l_end;
    }
    
    if (cmdctx->rtflags & CMDCTX_ISHELP) {
        rc = 1;
        goto l_end;
    }
    
    rc = cmd->do_cmd_fn(cmdctx);

 l_end:
    shInCmd = 0;
    
    if (cmd->destroy_cmd_arg_d && cmdctx->_data)
        cmd->destroy_cmd_arg_d(cmdctx->_data);

#if 0                           /* DUPA */
    if ((cmd->flags & COMMAND_MODIFIESDB) && cmdctx->sh_s->ts_instpkgs > 0) {
        cmdctx->sh_s->dbpkgdir->ts = cmdctx->sh_s->ts_instpkgs;
        cmdctx->sh_s->ts_instpkgs = 0;
    }
#endif    
    verbose = verbose_;
    return rc;
}

/* argp workaround */
static int argv_is_help(int argc, const char **argv)
{
    int i, is_help = 0;

    for (i=0; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-?") == 0 ||
            strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--usage") == 0) {
            
            is_help = 1;
            break;
        }
    }
    return is_help;
}


static int cmdctx_isctrlmsg(const char *fmt) 
{
    return *fmt == '!';
}

int cmdctx_printf(struct cmdctx *cmdctx, const char *fmt, ...)
{
    va_list args;
    int n = 0;
    
    if (cmdctx_isctrlmsg(fmt)) {
        if (cmdctx->rtflags & CMDCTX_NOCTRLMSGS)
            return 1;
        fmt++;
    }

    va_start(args, fmt);
    if (cmdctx->pipe_right)
        n = cmd_pipe_vprintf(cmdctx->pipe_right, fmt, args);
    else 
        n = vfprintf(stdout, fmt, args);

    va_end(args);
    return n;
    
}

int cmdctx_printf_c(struct cmdctx *cmdctx, int color, const char *fmt, ...)
{
    va_list args;
    int n = 0;

    if (cmdctx_isctrlmsg(fmt)) {
        if (cmdctx->rtflags & CMDCTX_NOCTRLMSGS)
            return 1;
        fmt++;
    }

    va_start(args, fmt);
    if (cmdctx->pipe_right)
        n = cmd_pipe_vprintf(cmdctx->pipe_right, fmt, args);
    else 
        n = vprintf_c(color, fmt, args);

    return n;
}

int cmdctx_addtoresult(struct cmdctx *cmdctx, struct pkg *pkg) 
{
    if (cmdctx->pipe_right)
        return cmd_pipe_writepkg(cmdctx->pipe_right, pkg);
    return 1;
}

static
int command_cmp(struct poclidek_cmd *c1, struct poclidek_cmd *c2) 
{
    return strcmp(c1->name, c2->name);
}

int poclidek_cmd_ncmp(struct poclidek_cmd *c1, struct poclidek_cmd *c2)
{
    return strncmp(c1->name, c2->name, strlen(c2->name));
}


static void init_commands(struct poclidek_ctx *cctx) 
{
    int n = 0;
	char   *homedir;
    
    cctx->commands = n_array_new(16, NULL, (tn_fn_cmp)command_cmp);
    n_array_ctl(cctx->commands, TN_ARRAY_AUTOSORTED);
    while (commands_tab[n] != NULL) {
        struct poclidek_cmd *cmd = commands_tab[n++];
        
        cmd->_seqno = n;
        if (cmd->argp_opts)
            translate_argp_options(cmd->argp_opts);

        cmd->arg = _(cmd->arg);
        cmd->doc = _(cmd->doc);
        
        
        if (n_array_bsearch(cctx->commands, cmd)) {
            logn(LOGERR, _("ambiguous command %s"), cmd->name);
            exit(EXIT_FAILURE);
        }
        n_array_push(cctx->commands, cmd);
        n_array_sort(cctx->commands);
    }
	n_array_sort(cctx->commands);

    poclidek_load_aliases(cctx, "/etc/poldek/alias");
	if ((homedir = getenv("HOME")) != NULL) {
		char path[PATH_MAX];
		snprintf(path, sizeof(path), "%s/.poldek.alias", homedir);	
		poclidek_load_aliases(cctx, path);
	}
    n_array_sort(cctx->commands);
}

static void *dent_alloc(struct poclidek_ctx *cctx, size_t size)
{
    return n_obstack_alloc(cctx->_dent_obstack, size);
}


int poclidek_init(struct poclidek_ctx *cctx, struct poldek_ctx *ctx)
{
    n_assert (cctx->ctx == NULL);
    cctx->flags = 0;
    cctx->ctx = ctx;
    cctx->pkgs_available = NULL;
    cctx->pkgs_installed = NULL;
    cctx->_dent_obstack = n_obstack_new(32);
    cctx->dent_alloc = dent_alloc;
    init_commands(cctx);
    return 1;
}


void poclidek_destroy(struct poclidek_ctx *cctx) 
{
    if (cctx->pkgs_available)
        n_array_free(cctx->pkgs_available);
    
    if (cctx->pkgs_installed)
        n_array_free(cctx->pkgs_installed);

    if (cctx->rootdir)
        pkg_dent_free(cctx->rootdir);

    if (cctx->dbpkgdir) {
        poclidek_save_installedcache(cctx, cctx->dbpkgdir);
        pkgdir_free(cctx->dbpkgdir);
    }
    
    memset(cctx, 0, sizeof(*cctx));
}


int poclidek_load_packages(struct poclidek_ctx *cctx, int skip_installed) 
{
    struct poldek_ctx *ctx;
    

    if (cctx->flags & POLDEKCLI_PACKAGES_LOADED)
        return 1;

    cctx->flags |= POLDEKCLI_PACKAGES_LOADED;

    ctx = cctx->ctx;
    
    if (!poldek_load_sources(ctx))
        return 0;

    cctx->pkgs_available = poldek_get_avpkgs_bynvr(ctx);
    poclidek_dent_init(cctx);
    
    poclidek_load_installed(cctx, 0); 
    
    cctx->pkgs_installed = NULL;
    if (skip_installed == 0) {
        
        n_array_ctl(cctx->pkgs_installed, TN_ARRAY_AUTOSORTED);
        //load_installed_packages(&shell_s, 0);
    }

    
    return 1;
}

static char **a_argv_to_argv(tn_array *a_argv, char **argv) 
{
    int i;
    for (i=0; i < n_array_size(a_argv); i++) {
        argv[i] = n_array_nth(a_argv, i);
        //printf("  %d. %s\n", j, argv[j]);
    }
    argv[i] = NULL;
    return argv;
}

tn_array *poclidek_prepare_cmdline(struct poclidek_ctx *cctx, const char *line);


static
int poclidek_exec_cmd_ent(struct poclidek_ctx *cctx, struct poldek_ts *ts,
                          struct cmd_chain_ent *ent)
{
    struct cmdctx  cmdctx;
    char **argv;
    int nerr = 0;
    
    DBGF("ent %s, %d, %p\n", ent->cmd->name, n_array_size(ent->a_argv),
         ent->next_piped);
    
    
    memset(&cmdctx, 0, sizeof(cmdctx));
    cmdctx.cmd = ent->cmd;
    cmdctx.cctx = cctx;
    if ((cmdctx.ts = ts) == NULL)
        cmdctx.ts = poldek_ts_new(cctx->ctx);

    if (ent->next_piped) {
        cmdctx.pipe_right = cmd_pipe_new();
        ent->pipe_right = cmdctx.pipe_right;
    }

    if (ent->prev_piped) {
        struct cmd_pipe *pipe;
        tn_array *pipe_args = NULL;

        pipe = ent->prev_piped->pipe_right;
        ent->prev_piped->pipe_right = NULL;
        
        cmdctx.pipe_left = pipe;

        if (ent->cmd->flags & COMMAND_PIPE_XARGS) {
            if (ent->cmd->flags & COMMAND_PIPE_PACKAGES)
                pipe_args = cmd_pipe_xargs(pipe, CMD_PIPE_CTX_PACKAGES);
            else
                pipe_args = cmd_pipe_xargs(pipe, CMD_PIPE_CTX_ASCII);
            
            if (pipe_args) {
                while (n_array_size(pipe_args))
                    n_array_push(ent->a_argv, n_array_shift(pipe_args));
            }
        }
    }
    

    argv = alloca((n_array_size(ent->a_argv) + 1) * sizeof(*argv));
    a_argv_to_argv(ent->a_argv, argv);

    nerr += do_exec_cmd_ent(&cmdctx, n_array_size(ent->a_argv), argv);
    
    if (ts == NULL) 
        poldek_ts_free(cmdctx.ts);

    if (ent->next_piped) {
        return poclidek_exec_cmd_ent(cctx, ts, ent->next_piped);
    }
    
    return nerr;
    
}

int poclidek_exec_line(struct poclidek_ctx *cctx, struct poldek_ts *ts,
                       const char *cmdline) 
{
    tn_array            *cmd_chain;
    int                 nerr = 0, i;

    DBGF("exec_line = %s\n", cmdline);
    
    cmd_chain = poclidek_prepare_cmdline(cctx, cmdline);
    if (cmd_chain == NULL)
        return 0;
    
    for (i=0; i < n_array_size(cmd_chain); i++) {
        struct cmd_chain_ent  *ent;
        
        ent = n_array_nth(cmd_chain, i);
        if (ent->flags & (CMD_CHAIN_ENT_SEMICOLON | CMD_CHAIN_ENT_PIPE)) {
            n_assert(0);
            continue;
        }

        poclidek_exec_cmd_ent(cctx, ts, ent);
    }

    return nerr == 0;
}


int poclidek_exec(struct poclidek_ctx *cctx, struct poldek_ts *ts, int argc,
                  const char **argv)
{
    char *cmdline;
    int  len, n, i ;

    len = 0;
    for (i=0; i < argc; i++)
        len += 2 * strlen(argv[i]);

    cmdline = alloca(len + 1);
    n = 0;
    
    for (i=0; i < argc; i++)
        n += n_snprintf(&cmdline[n], len - n, "%s ", argv[i]);
    
    return poclidek_exec_line(cctx, ts, cmdline);
}


void poclidek_apply_iinf(struct poclidek_ctx *cctx, struct install_info *iinf)
{
    int i, n = 0;
        
    if (iinf == NULL)
        return;
    
    if (cctx->pkgs_installed) {
        for (i=0; i < n_array_size(iinf->uninstalled_pkgs); i++) {
            struct pkg *pkg = n_array_nth(iinf->uninstalled_pkgs, i);
            n_array_remove(cctx->pkgs_installed, pkg);
            n++;
            printf("- %s\n", pkg->nvr);
        }
        
        for (i=0; i < n_array_size(iinf->installed_pkgs); i++) {
            struct pkg *pkg = n_array_nth(iinf->installed_pkgs, i);
            n_array_push(cctx->pkgs_installed, pkg_link(pkg));
            n++;
        }
        n_array_sort(cctx->pkgs_installed);
        
        //printf("s = %d\n", n_array_size(cctx->pkgs_installed));
        if (n)
            cctx->ts_instpkgs = time(0);
    }
}
