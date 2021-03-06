/*
  Copyright (C) 2000 - 2008 Pawel A. Gajda <mis@pld-linux.org>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  published by the Free Software Foundation (see file COPYING for details).

  You should have received a copy of the GNU General Public License along
  with this program; if not, write to the Free Software Foundation, Inc.,
  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <trurl/trurl.h>

#include "compiler.h"
#include "i18n.h"
#include "log.h"
#include "poldek_term.h"
#include "poldek_ts.h"
#include "poldek_intern.h"
#include "pkg.h"
#include "capreq.h"

#define msg_ask(fmt, args...) poldek_log(LOGTTY|LOGINFO, fmt, ## args)

static int term_confirm(void *foo, const struct poldek_ts *ts, int hint,
                        const char *question) 
{
    const char *yn = "[Y/n]";
    int a;

    foo = foo;
    ts = ts;
    
    if (!isatty(STDIN_FILENO))
        return hint;

    if (hint == 0)    /* no */
        yn = "[N/y]";

    msg_ask("%s %s", question, yn);
    
    a = poldek_term_ask(STDIN_FILENO, "YyNn\n", NULL);
    a = toupper(a);
    switch(a) {
        case 'Y': a = 1; break;
        case 'N': a = 0; break;
        case '\n': a = hint; break;
        default:
            n_assert(0);
    }
    msg_ask("_ %c\n", a ? 'y' : 'n');
    return a;
}

static int term_ts_confirm(void *foo, const struct poldek_ts *ts)
{
    int answer = 1;
    foo = foo;
    
    /* poldek__ts_display_summary(ts); */ /* already displayed */
    
    if (ts->type == POLDEK_TS_UNINSTALL) {
        if (ts->getop(ts, POLDEK_OP_CONFIRM_UNINST))
            answer = term_confirm(foo, ts, 0, _("Proceed?"));
        
    } else {
        if (ts->getop(ts, POLDEK_OP_CONFIRM_INST))
            answer = term_confirm(foo, ts, 1, _("Proceed?"));
        
    }
    
    return answer;
}

static int term_choose_equiv(void *foo, const struct poldek_ts *ts,
                             const struct pkg *pkg, const char *capname,
                             tn_array *candidates, int hint)
{
    char *validchrs, *p;
    int i, j, a, lines;
    char choice[] = "abcdefghijklmnopqrtsuvwxyz1234567890ABCDEFGHIJKLMNOPRSTUVWXYZ";

    foo = foo; ts = ts;
    j = 0, lines = 0;
    
    lines = poldek_term_get_height();
    if (lines <= 0) lines = 30;
    lines -= 6; // to show some info above
    if (lines < 6) lines = 6;
    if (lines > sizeof(choice)) lines = sizeof(choice);

    if (hint >= lines)     /* over ascii */
        j = (hint/lines)*lines; // first show page with hint
    
    if (!isatty(STDIN_FILENO))
        return hint;

    if (pkg) {
        msg_ask(_("%s: required \"%s\" is provided by the following packages:"),
                pkg_id(pkg), capname);
    } else {
        msg_ask(_("Required \"%s\" is provided by the following packages:"),
                capname);
    }
    
    msg_ask("_\n");

    validchrs = alloca(100);
onemoretime:
    memset(&validchrs[0], 0, sizeof(validchrs));
    p = validchrs;
    *p++ = '\n';

    if (j > 0) {
	msgn(-1, _("-/backspace/pgup) page up"));
	*p++ = '-';
	*p++ = 0x7f; // backspace
    } 
    for (i = 0; i+j < n_array_size(candidates); i++) {
        msgn(-1, "%c) %s", choice[i], pkg_id(n_array_nth(candidates, i+j)));
        *p++ = choice[i];

        if (i > lines - 1)
            break;
    }
    if (i+j < n_array_size(candidates)) {
	msgn(-1, _("+/space/tab/pgdown) page down")); 
	*p++ = '+';
	*p++ = ' ';  // space
	*p++ = '\t'; // tab
    }

    *p++ = 'Q';

    msg_ask(_("Which one do you want to install ('Q' to abort)? [%s]"), pkg_id(n_array_nth(candidates, hint)));
    
    a = poldek_term_ask(STDIN_FILENO, validchrs, NULL);
    msg_ask("_\n");

    if (a == '-' || a == 0x7f) {
	if (j >= lines) j -= lines;
        goto onemoretime;
    }

    if (a == '+' || a == ' ' || a == '\t' ) {
	if (j + lines < n_array_size(candidates)) j += lines;
        goto onemoretime;
    }

    if (a == '\n')
        return hint;

    if (a == 'Q')
        return -1;

    a = strchr(choice, a) - choice;
    if (a >= 0 && a <= i)
        return a + j;
    
    return hint;
}

static int term_choose_suggests(void *foo, const struct poldek_ts *ts, 
                                const struct pkg *pkg, tn_array *caps,
                                tn_array *choices, int hint)
{
    char message[512], *question;
    char *yns = "N/y/s", *yn = "N/y";
    int i, a, ac;
    
    foo = foo; ts = ts;
    
    if (!isatty(STDIN_FILENO))
        return hint;

    if (hint) {
        yns = "Y/n/s";
        yn = "Y/n";
    }

    n_snprintf(message, sizeof(message),
               _("Package %s suggests installation of:"), pkg_id(pkg));

    question = ngettext("Try to install it?", "Try to install them?",
                        n_array_size(caps));    

    msg_ask("%s\n", message);
    
    for (i=0; i < n_array_size(caps); i++) {
        struct capreq *cap = n_array_nth(caps, i);
        msgn(-1, "%d. %s", i + 1, capreq_stra(cap));
    }

    if (n_array_size(caps) > 1) {
        msg_ask("%s ", question);
        msg_ask(_("(y - all, n - nothing, s - select some of)? [%s]"),
                yns);

        a = poldek_term_ask(STDIN_FILENO, "YyNnSs\n", NULL);
    } else {
        msg_ask("%s [%s]", question, yn);
        
        a = poldek_term_ask(STDIN_FILENO, "YyNn\n", NULL);
    }

    a = toupper(a);
    switch(a) {
        case 'Y': a = 1; ac = 'y'; break;
        case 'N': a = 0; ac = 'n'; break;
        case 'S': a = 2; ac = 's'; break;
        case '\n': a = hint; ac = hint ? 'y':'n'; break;
        default:
            n_assert(0);
    }
    msg_ask("_ %c\n", ac);
    
    if (a == 2) {
        for (i=0; i < n_array_size(caps); i++) {
            struct capreq *cap = n_array_nth(caps, i);
            char q[512];
            n_snprintf(q, sizeof(q), _("Try to install %s?"), capreq_stra(cap));
            
            if (term_confirm(NULL, NULL, 1, q))
                n_array_push(choices, cap);
        }
    }

    return a;
}

int poldek__confirm(const struct poldek_ts *ts, int hint, const char *message)
{
    if (ts->ctx->confirm_fn == NULL)
        return hint;

    return ts->ctx->confirm_fn(ts->ctx->data_confirm_fn, ts, hint, message);
}

int poldek__ts_confirm(const struct poldek_ts *ts)
{
    if (ts->ctx->ts_confirm_fn == NULL)
        return 1;

    return ts->ctx->ts_confirm_fn(ts->ctx->data_ts_confirm_fn, ts);
}

int poldek__choose_equiv(const struct poldek_ts *ts,
                         const struct pkg *pkg, const char *capname,
                         tn_array *pkgs, struct pkg *hint)
{
    int i, inthint = 0;
    
    if (hint) {
        for (i=0; i < n_array_size(pkgs); i++) {
            if (hint && hint == n_array_nth(pkgs, i)) {
                inthint = i;
                break;
            }
        }
    }

    if (ts->ctx->choose_equiv_fn == NULL)
        return inthint;
    
    return ts->ctx->choose_equiv_fn(ts->ctx->data_choose_equiv_fn,
                                    ts, pkg, capname, pkgs, inthint);
}

int poldek__choose_suggests(const struct poldek_ts *ts,
                            const struct pkg *pkg, tn_array *caps,
                            tn_array *choices, int hint)
{
    if (ts->ctx->choose_suggests_fn == NULL)
        return hint;

    return ts->ctx->choose_suggests_fn(ts->ctx->data_choose_suggests_fn,
                                       ts, pkg, caps, choices, hint);
}


void poldek__setup_default_ask_callbacks(struct poldek_ctx *ctx)
{
    ctx->data_confirm_fn = NULL;
    ctx->confirm_fn = term_confirm;

    ctx->data_ts_confirm_fn = NULL;
    ctx->ts_confirm_fn = term_ts_confirm;

    ctx->data_choose_equiv_fn = NULL;
    ctx->choose_equiv_fn = term_choose_equiv;

    ctx->data_choose_suggests_fn = NULL;
    ctx->choose_suggests_fn = term_choose_suggests;
}
