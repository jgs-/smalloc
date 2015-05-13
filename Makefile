kernel:
	cd /usr/src/sys/arch/amd64/compile/GENERIC; make -f Makefile

install:
	cd /usr/src/sys/arch/amd64/compile/GENERIC; make -f Makefile install

libsmalloc:
	gcc -fPIE -shared -o libsmalloc.so libsmalloc.c

test:
	LD_PRELOAD=/home/jgs/smalloc/libsmalloc.so ./a 512
