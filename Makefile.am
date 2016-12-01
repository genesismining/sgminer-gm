
ACLOCAL_AMFLAGS = -I m4

JANSSON_CPPFLAGS= -I$(top_builddir)/submodules/jansson/src -I$(top_srcdir)/submodules/jansson/src

EXTRA_DIST	= example.conf m4/gnulib-cache.m4 \
		  ADL_SDK/readme.txt api-example.php miner.php	\
		  API.class API.java api-example.c hexdump.c \
		  doc/API doc/FAQ doc/GPU doc/SCRYPT doc/windows-build.txt

SUBDIRS		= lib submodules ccan sph

bin_PROGRAMS     = sgminer

sgminer_CPPFLAGS = $(PTHREAD_FLAGS) -std=gnu99 $(JANSSON_CPPFLAGS)
sgminer_LDFLAGS  = $(PTHREAD_FLAGS)
sgminer_LDADD    = $(DLOPEN_FLAGS) @LIBCURL_LIBS@ @JANSSON_LIBS@ @PTHREAD_LIBS@ \
		  @OPENCL_LIBS@ @NCURSES_LIBS@ @PDCURSES_LIBS@ @WS2_LIBS@ \
		  @MM_LIBS@ @RT_LIBS@ @MATH_LIBS@ lib/libgnu.a ccan/libccan.a sph/libsph.a

sgminer_CPPFLAGS += -I$(top_builddir)/lib -I$(top_srcdir)/lib @OPENCL_FLAGS@ @LIBCURL_CFLAGS@

if HAVE_WINDOWS
sgminer_LDFLAGS += -all-static -Wl,--stack,4194304
endif

sgminer_CPPFLAGS += $(ADL_CPPFLAGS)

if USE_GIT_VERSION
GIT_VERSION      := $(shell sh -c 'git describe --abbrev=4 --dirty')
sgminer_CPPFLAGS += -DGIT_VERSION=\"$(GIT_VERSION)\"
endif

if USE_BUILD_NUMBER
sgminer_CPPFLAGS += -DBUILD_NUMBER=\"$(BUILD_NUMBER)\"
endif

sgminer_SOURCES := sgminer.c
sgminer_SOURCES	+= api.c api.h
sgminer_SOURCES	+= elist.h miner.h compat.h bench_block.h
sgminer_SOURCES	+= util.c util.h uthash.h
sgminer_SOURCES	+= logging.c logging.h
sgminer_SOURCES += driver-opencl.c driver-opencl.h
sgminer_SOURCES += ocl.c ocl.h
sgminer_SOURCES += findnonce.c findnonce.h
sgminer_SOURCES += adl.c adl.h adl_functions.h
sgminer_SOURCES += sysfs-gpu-controls.c sysfs-gpu-controls.h
sgminer_SOURCES += pool.c pool.h
sgminer_SOURCES += algorithm.c algorithm.h
sgminer_SOURCES += config_parser.c config_parser.h
sgminer_SOURCES += events.c events.h
sgminer_SOURCES += ocl/build_kernel.c ocl/build_kernel.h
sgminer_SOURCES += ocl/binary_kernel.c ocl/binary_kernel.h

sgminer_SOURCES += kernel/*.cl
sgminer_SOURCES += algorithm/scrypt.c algorithm/scrypt.h
sgminer_SOURCES += algorithm/darkcoin.c algorithm/darkcoin.h
sgminer_SOURCES += algorithm/qubitcoin.c algorithm/qubitcoin.h
sgminer_SOURCES += algorithm/quarkcoin.c algorithm/quarkcoin.h
sgminer_SOURCES += algorithm/myriadcoin-groestl.c algorithm/myriadcoin-groestl.h
sgminer_SOURCES += algorithm/fuguecoin.c algorithm/fuguecoin.h
sgminer_SOURCES += algorithm/inkcoin.c algorithm/inkcoin.h
sgminer_SOURCES += algorithm/animecoin.c algorithm/animecoin.h
sgminer_SOURCES += algorithm/groestlcoin.c algorithm/groestlcoin.h
sgminer_SOURCES += algorithm/sifcoin.c algorithm/sifcoin.h
sgminer_SOURCES += algorithm/twecoin.c algorithm/twecoin.h
sgminer_SOURCES += algorithm/marucoin.c algorithm/marucoin.h
sgminer_SOURCES += algorithm/maxcoin.c algorithm/maxcoin.h
sgminer_SOURCES += algorithm/talkcoin.c algorithm/talkcoin.h
sgminer_SOURCES += algorithm/bitblock.c algorithm/bitblock.h
sgminer_SOURCES += algorithm/x14.c algorithm/x14.h
sgminer_SOURCES += algorithm/fresh.c algorithm/fresh.h
sgminer_SOURCES += algorithm/whirlcoin.c algorithm/whirlcoin.h
sgminer_SOURCES += algorithm/neoscrypt.c algorithm/neoscrypt.h
sgminer_SOURCES += algorithm/whirlpoolx.c algorithm/whirlpoolx.h
sgminer_SOURCES += algorithm/lyra2re.c algorithm/lyra2re.h algorithm/lyra2.c algorithm/lyra2.h algorithm/sponge.c algorithm/sponge.h
sgminer_SOURCES += algorithm/lyra2rev2.c algorithm/lyra2rev2.h
sgminer_SOURCES += algorithm/pluck.c algorithm/pluck.h
sgminer_SOURCES += algorithm/credits.c algorithm/credits.h
sgminer_SOURCES += algorithm/yescrypt.h algorithm/yescrypt.c algorithm/yescrypt_core.h algorithm/yescrypt-opt.c algorithm/yescryptcommon.c algorithm/sysendian.h
sgminer_SOURCES += algorithm/blake256.c algorithm/blake256.h
sgminer_SOURCES += algorithm/blakecoin.c algorithm/blakecoin.h
sgminer_SOURCES += algorithm/ethash.c algorithm/ethgencache.c algorithm/ethash.h algorithm/eth-sha3.c algorithm/eth-sha3.h
sgminer_SOURCES += algorithm/cryptonight.c algorithm/cryptonight.h algorithm/cn-aes-tbls.h
sgminer_SOURCES += algorithm/equihash.c algorithm/equihash.h
sgminer_SOURCES += gbt-util.c gbt-util.h

bin_SCRIPTS	= $(top_srcdir)/kernel/*.cl

