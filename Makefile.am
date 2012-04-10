# Copyright (C) 2012 Daiki Ueno <ueno@unixuser.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SUBDIRS = lib .
ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = m4/gnulib-cache.m4 git.mk

bin_PROGRAMS = gpass-export

gpass_export_CFLAGS =				\
	$(LIBGCRYPT_CFLAGS)			\
	$(GPGME_CFLAGS)				\
	-I$(top_srcdir)/lib			\
	$(NULL)

gpass_export_LDADD =				\
	$(LIBGCRYPT_LIBS)			\
	$(GPGME_LIBS)				\
	$(top_builddir)/lib/libgnu.a		\
	$(NULL)

gpass_export_SOURCES = gpass-export.c

distclean-local:
	if test "x$(srcdir)" = "x."; then :; else \
		rm -f ChangeLog; \
	fi

MAINTAINERCLEANFILES =				\
	$(srcdir)/ChangeLog			\
	$(NULL)

ChangeLog:
	@echo Creating $@
	@if test -d "$(srcdir)/.git"; then \
	  (GIT_DIR=$(top_srcdir)/.git ./missing --run git log --stat) | fmt --split-only > $@.tmp \
	  && mv -f $@.tmp $@ \
	  || ($(RM) $@.tmp; \
	      echo Failed to generate ChangeLog, your ChangeLog may be outdated >&2; \
	      (test -f $@ || echo git-log is required to generate this file >> $@)); \
	else \
	  test -f $@ || \
	  (echo A git checkout and git-log is required to generate ChangeLog >&2 && \
	  echo A git checkout and git-log is required to generate this file >> $@); \
	fi

.PHONY: ChangeLog

GITIGNOREFILES =                                \
	INSTALL					\
	aclocal.m4				\
	compile					\
	config.guess				\
	config.h.in				\
	config.sub				\
	depcomp					\
	install-sh				\
	missing					\
	mkinstalldirs				\
	m4					\
	lib					\
	snippet					\
	$(NULL)

-include $(top_srcdir)/git.mk
