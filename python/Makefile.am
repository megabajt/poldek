SWIG = swig -python -shadow
py_ver     = $(shell python -c "import sys; print sys.version[:3]")
py_prefix  = $(shell python -c "import sys; print sys.prefix")
py_incdir  = $(py_prefix)/include/python$(py_ver)

EXTRA_DIST = poldekmod.i local_stdint.c pyldek.py run.sh
CLEANFILES = wrap_* poldekmod.py local_stdint.h

AM_CPPFLAGS = @TRURL_INCLUDE@ @TNDB_INCLUDE@ -I$(top_srcdir) -I$(py_incdir) -I.

#pythondir = $(prefix)$(libdir)/python
python_PYTHON = poldek.py
python_PYTHON += poldekmod.py

lib_LTLIBRARIES = _poldekmod.la
_poldekmod_la_SOURCES = wrap_poldekmod.c
_poldekmod_la_LDFLAGS = -avoid-version -module
_poldekmod_la_LIBADD = ../libpoldek.la ../vfile/libvfile.la ../cli/libpoclidek.la @TRURL_LDFLAG@ 

AM_CFLAGS=
CFLAGS=
CPPFLAGS += -DSWIG -DPOCLIDEK_ITSELF 

poldekmod.i: local_stdint.h

#install-exec-hook:
#	$(mkinstalldirs) "$(DESTDIR)$(py_sitedir)"

poldekmod.py: wrap_poldekmod.c

local_stdint.h: local_stdint.c
	$(CPP) $< > $@

#wrap_poldekmod.c: poldekmod.i
#	$(SWIG) $(SWIG_PYTHON_OPT) $(INCLUDES) -I/usr/include -o $@ $<

wrap_%.c: %.i
	$(SWIG) $(SWIG_PYTHON_OPT) $(AM_CPPFLAGS) -I/usr/include -o $@ $<

clean-local:
	-rm -f core *.o *.bak *~ *.pyc *.pyo
