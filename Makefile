#
# Grand Unified Makefile for Xen.
#
# Keir Fraser, 6/5/2003
#
# Builds everything except Xenolinux:
#  cd xenolinux-<version>-sparse
#  ./mkbuildtree <build dir>
#  cd <build dir> && make oldconfig && make dep && make bzImage
#  (<build dir> should be a vanilla linux tree with matching version)
#
# If you get errors in tools/domctl or tools/vdmanager, then you need
# the latest Java 2 SDK on your execution path: <http://java.sun.com>
# Also, you will need Apache's 'ant' build tool: <http://ant.apache.org>
#
# If you received this source as part of a Xen release, you should find
# that appropriate versions of the build tools are already installed in
# the initial system setup.

all:	
	$(MAKE) -C xen
	$(MAKE) -C tools

install: all
	$(MAKE) -C xen install
	$(MAKE) -C tools install

clean:
	$(MAKE) -C xen clean
	$(MAKE) -C tools clean

