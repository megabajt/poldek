/*
  Copyright (C) 2000 - 2002 Pawel A. Gajda <mis@k2.net.pl>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  published by the Free Software Foundation (see file COPYING for details).

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/


#if HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STRSIGNAL
# define _GNU_SOURCE 1
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#if HAVE_OPENPTY
# include <pty.h>
# include <termios.h>
#endif

#include <trurl/nassert.h>
#include <trurl/nmalloc.h>

#include "i18n.h"
#include "vopen3.h"

#define P_OPEN_EXITED   (1 << 16) 

void vopen3_init(struct vopen3_st *st, const char *cmd, char *const argv[]) 
{
    memset(st, 0,  sizeof(*st));
    
    if (cmd)
        st->cmd = n_strdup(cmd);
    
    if (argv && argv[0]) {
        int n = 0;
        
        while (argv[n++])
            ;
        st->argv = n_malloc(n * sizeof(*st->argv));

        n = 0;
        while (argv[n]) {
            st->argv[n] = strdup(argv[n]);
            n++;
        }
        st->argv[n] = NULL;
    }
    
    st->errmsg = NULL;
}

static void my_fclose(FILE **stream)
{
    if (*stream) {
        fclose(*stream);
        *stream = NULL;
    }
}


void vopen3_destroy(struct vopen3_st *st) 
{
    my_fclose(&st->stream_in);
    my_fclose(&st->stream_out);
    my_fclose(&st->stream_err);
    
    if (st->cmd) {
        free(st->cmd);
        st->cmd = NULL;
    }

    
    if (st->argv) {
        int n = 0;
        while (st->argv[n])
            free(st->argv[n++]);
        
        free(st->argv);
        st->argv = NULL;
    }
    
    if (st->errmsg) {
        free(st->errmsg);
        st->errmsg = NULL;
    }
}


static void p_dupnull(int fdno, unsigned p_open_flags) 
{
    switch (fdno) {
        case STDIN_FILENO:
            if ((p_open_flags & VOPEN3_SHARE_STDIN) == 0) {
                int fd;
                if ((fd = open("/dev/null", O_RDONLY)) < 0) {
                    fprintf(stderr, "open /dev/null: %m\n");
                    return;
                }
                dup2(fd, STDIN_FILENO);
                close(fd);
            }
            break;
            
        default:
            n_assert(0);
    }
}

static void st_seterr(struct vopen3_st *st, const char *fmt, ...)
{
    va_list args;
    char   errmsg[1024];

    va_start(args, fmt);
    vsnprintf(errmsg, sizeof(errmsg), fmt, args);
    st->errmsg = n_strdup(errmsg);
    va_end(args);
}


static int check_cmd(struct vopen3_st *st, const char *cmd) 
{
    if (access(cmd, R_OK | X_OK) != 0) {
        st_seterr(st, _("%s: no such file"), cmd);
        return 0;
    }
    return 1;
}

struct p_pipe {
    int in_fd; 
    int out_fd;
};

static int p_pipe_creat(struct vopen3_st *st, struct p_pipe *pi)
{
    int pp[2];
    
    if (pipe(pp) != 0) {
        st_seterr(st, "pipe: %m");
        return 0;
    }

    pi->out_fd = pp[0];
    pi->in_fd  = pp[1];
    printf("PIPE [->%d, %d->]\n", pi->in_fd, pi->out_fd);
    return 1;
}

static void p_pipe_close(struct p_pipe *pi)
{
    if (pi->out_fd)
        close(pi->out_fd);

    if (pi->in_fd)
        close(pi->in_fd);
}


int vopen3_exec(struct vopen3_st *vst, unsigned flags)
{
    struct vopen3_st *st, *st_prev;
    pid_t  pid;
    int    is_chain = 0;
    

    if (vst->next)
        is_chain = 1;
    
    st = vst;
    st_prev = NULL;
    
    while (st) {
        struct p_pipe out_pipe, in_pipe;
        
        n_assert(st->stream_out == NULL);
        
        if (!p_pipe_creat(st, &out_pipe))
            break;
    
        if (is_chain && st_prev) {
            in_pipe.out_fd = st_prev->fd_out;
            in_pipe.in_fd = -1;
            
        } else if (!p_pipe_creat(st, &in_pipe))
            break;

        if ((pid = fork()) < 0) {
            st_seterr(st, "fork %s: %m", st->cmd);
            break;
            
        } else if (pid == 0) {  /* child */
            int i;
            
            printf("[%d] exec %s [->%d, %d->]\n", getpid(), 
                   st->cmd, out_pipe.in_fd, in_pipe.out_fd);
            
            dup2(out_pipe.in_fd, STDOUT_FILENO);
            dup2(out_pipe.in_fd, STDERR_FILENO);
            p_pipe_close(&out_pipe);
            
            if (st_prev == NULL) { /* head */
                if ((flags & VOPEN3_SHARE_STDIN))
                    dup2(in_pipe.out_fd, STDIN_FILENO);
                else
                    p_dupnull(STDIN_FILENO, flags);
            }
        
            p_pipe_close(&in_pipe);
            
            for (i = 3; i < 100; i++)
                close(i);

            if (execv(st->cmd, st->argv) < 0) {
                printf("execv %s: %m\n", st->cmd);
            }
            
            exit(EXIT_FAILURE);
        
        } else {                /* me */
            close(out_pipe.in_fd);
            close(in_pipe.out_fd);

            st->fd_in = -1;
            st->fd_out = out_pipe.out_fd;
            st->pid = pid;


            if (st_prev == NULL) {
                fprintf(stdout, "%s: fd_in %d\n", st->cmd, in_pipe.in_fd);
                st->fd_in = in_pipe.in_fd;
            }
            printf("[%d] Pexec %s [->%d, %d->]\n", st->pid, 
                   st->cmd, st->fd_in, st->fd_out);
        }
        
        st_prev = st;
        st = st->next;
    }

    st = vst;
    while (st) {
        printf("EX %d %d, %d\n", st->pid, st->fd_in, st->fd_out);
        st = st->next;
    }
    
    return vst->fd_in;
}


static
int do_waitpid(struct vopen3_st *st, int woptions) 
{
    int status = 0, rc = -1;
    pid_t pid;


    if (st->pid == 0)          /* exited */
        return st->ec;
    
    if (st->errmsg)
        free(st->errmsg);
    
    st->errmsg = NULL;
    printf("do_waitpid %d\n", st->pid);
    
    if ((pid = waitpid(st->pid, &status, woptions)) < 0) {
        printf("waitpid %s: %m\n", st->cmd);
        return 0;
    }
    
    if (pid == 0)
        return 0;

    if (WIFEXITED(status)) {
        rc = WEXITSTATUS(status);
        
    } else if (WIFSIGNALED(status)) {
#ifdef HAVE_STRSIGNAL
        st_seterr(st, _("%s terminated by signal %d (%s)"),
                   st->cmd, WTERMSIG(status), strsignal(WTERMSIG(st)));
#else
        st_seterr(st, _("%s terminated by signal %d"),
                   st->cmd, WTERMSIG(status));
#endif        
        
    } else {
        st_seterr(st, _("%s (%d) died under inscrutable circumstances"),
                   st->cmd, st->pid);
    }

    st->ec = rc;
    st->pid = 0;
    return rc;
}

int vopen3_st_isrunning(struct vopen3_st *st)
{
    while (st) {
        if (st->pid != 0)
            return 1;
        
        st = st->next;
    }
    return 0;
}


static int p_waitpid(struct vopen3_st *st, int woptions)
{
    int _woptions = 0, nfinished, n;
    struct vopen3_st *tmp;

    
    _woptions |= woptions;
    if (st->next)
        _woptions |= WNOHANG;

    nfinished = 0;
    tmp = st;
    n = 0;
    while (tmp) {
        if (tmp->pid == 0)
            nfinished++;
        tmp = tmp->next;
        n++;
    }
    printf("p_waitpid (%d, %d)\n", n, nfinished);
    while (1) {
        tmp = st;
        
        while (tmp) {
            if (tmp->pid != 0) {
                do_waitpid(tmp, _woptions);
                if (tmp->pid == 0)
                    nfinished++;
            }
            tmp = tmp->next;
            if (n == nfinished)
                goto l_end;
        }
        
        if (woptions & WNOHANG)
            goto l_end;
    }

 l_end:
    printf("END p_waitpid (%d, %d)\n", n, nfinished);
    return n == nfinished;
}

        

int vopen3_wait(struct vopen3_st *st) 
{
    return p_waitpid(st, WNOHANG);
}

int vopen3_close(struct vopen3_st *st) 
{
    p_waitpid(st, 0);
    return st->ec;
}


int vopen3_chain(struct vopen3_st *st1, struct vopen3_st *st2) 
{
    struct vopen3_st *st;

    st = st1;
    while (st->next && st->next->next)
        st = st->next;
    
    n_assert(st->next == NULL);
    st->next = st2;
    return 1;
}


void vopen3_process(struct vopen3_st *st, int verbose_level) 
{
    struct vopen3_st *head_st = st;
    int endl = 1, yes = 1;

    
    while (st->next) /* get the last proccess from chain */
        st = st->next;
    
    printf("last[%d] = %s, %d\n", st->pid, st->cmd, st->fd_out);


    ioctl(st->fd_out, FIONBIO, &yes);
    
    while (1) {
        struct timeval to = { 0, 200000 };
        fd_set fdset;
        int rc;
        
        FD_ZERO(&fdset);
        FD_SET(st->fd_out, &fdset);
        if ((rc = select(st->fd_out + 1, &fdset, NULL, NULL, &to)) < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            printf("BREAK0 (%d) %d: %m\n", rc, st->fd_out);
            break;
            
        } else if (rc == 0) {
            vopen3_wait(head_st);
            if (!vopen3_st_isrunning(head_st))
                break;
            
        } else if (rc > 0) {
            char  buf[4096];
            int   n, i;

            if ((n = read(st->fd_out, buf, sizeof(buf) - 1)) <= 0) {
                printf("BREAK %d: %m\n", n);
                break;
            }
            
            
            buf[n] = '\0';

            if (st->nread == 0)
                printf("out: [ ");

            st->nread += n;

            for (i=0; i < n; i++) {
                int c = buf[i];
                
                if (c == '\r')
                    continue;
                
                if (c == '\n') {
                    printf(" ]\n");
                    printf("out: [ ");
                    continue;
                }
                printf("%c", c);
            }
        }
    }
    printf("END %d\n", vopen3_st_isrunning(head_st));
    return;
}



#ifdef HAVE_OPENPTY
pid_t forkptysxx(int *master, struct termios *tios, struct winsize *wsize,
               char *errmsg, int errmsg_size) 
{
    int slave;
    pid_t pid;
    
    
    if (openpty(master, &slave, NULL, tios, wsize) != 0) {
        snprintf(errmsg, errmsg_size, "openpty: %m");
        return -1;
    }	
    
    if ((pid = fork()) == 0) {
        close(*master);
        dup2(slave, STDOUT_FILENO);
        dup2(slave, STDERR_FILENO);
        return 0;
    }
    
    return pid;
}

#if 0
static
FILE *pty_open(struct vopen3_st *st, unsigned flags, const char *cmd,
               char *const argv[])
{
    struct termios  termios;
    struct winsize  winsize;
    int             fd;
    pid_t           pid;
    char            errmsg[512];

    if (!isatty(STDOUT_FILENO))
        return pp_open(st, flags, cmd, argv);

    st->stream = NULL;
    
    if (tcgetattr(STDOUT_FILENO, &termios) != 0) {
        st_seterr(st, "tcgetattr(1): %m");
        return NULL;
    }
    
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &winsize) != 0) {
        st_seterr(st, "ioctl(1, TIOCGWINSZ): %m");
        return NULL;
    }
    
    if (access(cmd, R_OK | X_OK) != 0) {
        st_seterr(st, _("%s: no such file"), cmd);
        return NULL;
    }
    
    *errmsg = '\0';
    if ((pid = forkptys(&fd, &termios, &winsize,
                        errmsg, sizeof(errmsg))) == 0) {
        p_dupnull(STDIN_FILENO, flags);
        execv(cmd, argv);
        exit(EXIT_FAILURE);
        
    } else if (pid < 0) {
        if (*errmsg == '\0')
            st_seterr(st, "fork %s: %m", cmd);
        
    } else {
        st->fd = fd;
        st->stream = fdopen(fd, "r");
        setvbuf(st->stream, NULL, _IONBF, 0);
        st->pid = pid;
        st->cmd = n_strdup(cmd);
    }
    
    return st->stream;
}
#endif


#endif /* HAVE_OPENPTY */
