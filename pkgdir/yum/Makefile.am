NULL =

AM_CPPFLAGS = @TRURL_INCLUDE@ -I$(top_srcdir) -I$(top_srcdir)/pkgdir

LIBS=
noinst_LTLIBRARIES = libpkgdir_yum.la
libpkgdir_yum_la_SOURCES = 			\
	yum.c					\
	$(NULL)

libpkgdir_yum_la_CFLAGS =			\
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
