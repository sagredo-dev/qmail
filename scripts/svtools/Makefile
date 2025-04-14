PREFIX=/usr/local
BINDIR=$(PREFIX)/bin
SBINDIR=$(PREFIX)/sbin
MANDIR=$(PREFIX)/share/man

TITLE=svtools
VERSION=0.6

all: man

man: svdir.1 mltail.1 mlcat.1 mlhead.1 mltac.1 svsetup.1 svinitd.1 svinfo.1 \
     svinitd-create.1

svdir.1: svdir
	help2man -n "Find daemontools service directory" -N ./svdir > svdir.1
	
mltail.1: mltail
	help2man -n "tail frontend for multilog files" -N ./mltail > mltail.1
	
mlcat.1: mlcat
	help2man -n "cat frontend for multilog files" -N ./mlcat > mlcat.1
	
mlhead.1: mlhead
	help2man -n "head frontend for multilog files" -N ./mlhead > mlhead.1
	
mltac.1: mltac
	help2man -n "tac frontend for multilog files" -N ./mltac > mltac.1
	
svsetup.1: svsetup
	help2man -n "Service setup tool for daemontools" -N ./svsetup > svsetup.1
	
svinitd.1: svinitd
	help2man -n "init.d wrapper for daemontools services" -N ./svinitd > svinitd.1
	
svinitd-create.1: svinitd-create
	help2man -n "Create an init.d-script for a supervised process" -N ./svinitd-create > svinitd-create.1
	
svinfo.1: svinfo
	help2man -n "Get infos about a supervised process" -N ./svinfo > svinfo.1
	
install: all
	mkdir -p $(DESTDIR)$(BINDIR)
	cp -f \
	  svdir \
	  svinfo \
	  mltail \
	  mlcat \
	  mlhead \
	  mltac \
	  $(DESTDIR)$(BINDIR)
	cp -f \
	  svinitd \
	  svinitd-create \
	  svsetup \
	  $(DESTDIR)$(SBINDIR)
	mkdir -p $(DESTDIR)$(MANDIR)/man1
	cp -f \
	  svinitd.1 \
	  svinitd-create.1 \
	  svsetup.1 \
	  svdir.1 \
	  svinfo.1 \
	  mltail.1 \
	  mlcat.1 \
	  mlhead.1 \
	  mltac.1 \
	  $(DESTDIR)$(MANDIR)/man1

uninstall:
	rm -f \
	  $(DESTDIR)$(SBINDIR)/svinitd \
	  $(DESTDIR)$(SBINDIR)/svinitd-create \
	  $(DESTDIR)$(SBINDIR)/svsetup \
	  $(DESTDIR)$(BINDIR)/svdir \
	  $(DESTDIR)$(BINDIR)/svinfo \
	  $(DESTDIR)$(BINDIR)/mltail \
	  $(DESTDIR)$(BINDIR)/mlcat \
	  $(DESTDIR)$(BINDIR)/mlhead \
	  $(DESTDIR)$(BINDIR)/mltac
	rm -f \
	  $(DESTDIR)$(MANDIR)/man1/svinitd.1 \
	  $(DESTDIR)$(MANDIR)/man1/svinitd-create.1 \
	  $(DESTDIR)$(MANDIR)/man1/svsetup.1 \
	  $(DESTDIR)$(MANDIR)/man1/svdir.1 \
	  $(DESTDIR)$(MANDIR)/man1/svinfo.1 \
	  $(DESTDIR)$(MANDIR)/man1/mltail.1 \
	  $(DESTDIR)$(MANDIR)/man1/mlcat.1 \
	  $(DESTDIR)$(MANDIR)/man1/mlhead.1 \
	  $(DESTDIR)$(MANDIR)/man1/mltac.1

dist: clean
	mkdir $(TITLE)-$(VERSION)
	find * -not -regex ".*CVS.*" -and -not -regex ".*$(TITLE)-$(VERSION).*" -exec cp -f {} $(TITLE)-$(VERSION)/{} \;
	tar cfj $(TITLE)-$(VERSION).tar.bz2 $(TITLE)-$(VERSION)
	rm -rf $(TITLE)-$(VERSION)

clean:
	rm -f *.1
	rm -f $(TITLE)-$(VERSION).tar.bz2
