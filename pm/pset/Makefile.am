NULL =

AM_CPPFLAGS = @TRURL_INCLUDE@ -I$(top_srcdir)
AM_CFLAGS = @AM_CFLAGS@

LIBS=
noinst_LTLIBRARIES = libpm_pset.la
libpm_pset_la_SOURCES = 			\
	mod.c					\
	pset.c					\
	pm_pset.h				\
	$(NULL)

libpm_pset_la_CFLAGS =				\
	$(WARNINGFLAGS_C)			\
	$(NULL)

dist-hook:
	rm -rf $(distdir)/.deps

clean-local:
	-rm -f core *.o *.bak *~ *% *\# TAGS gmon.out \#* *\#


MAINTAINERCLEANFILES =	mkinstalldirs install-sh missing *.tar.gz *.spec \
			config.h.in configure Makefile.in config.h \
			config.sub config.guess aclocal.m4 \
			libtool ltconfig ltmain.sh stamp-h* depcomp *.1 
