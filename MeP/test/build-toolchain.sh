#!/usr/bin/env bash
# Build the GNU MeP toolchain the tests use, from pinned upstream tarballs:
#   binutils 2.45 (mep-elf-as/ld/objdump; its build tree also provides the libopcodes that
#   slotdis.c links against), GCC 6.5.0 (C only; MeP was removed in GCC 7) and newlib 4.5.0.
#   test/build-toolchain.sh <workdir> <prefix>
# Afterwards put <prefix>/bin on PATH and set BU_BUILD=<workdir>/build-binutils.
# Needs a host C/C++ compiler, make, curl. GCC 6.5 on a current host needs:
#   - C/C++ dialect flags (-std=gnu99 / -std=gnu++98 -fpermissive), --enable-obsolete (MeP was
#     deprecated in GCC 6), and no gotools/libgo;
#   - libgcc without the DWARF unwinder: GCC 6.5's MeP back end ICEs on unwind-dw2.c
#     ("in pre_and_rev_post_order_compute"); C programs do not need it.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
P=$(mkdir -p "$2" && cd "$2" && pwd)
J=${JOBS:-$(nproc)}
fetch() { # url sha256
	local f=$W/$(basename "$1")
	[[ -f $f ]] || curl -fsSL -o "$f" "$1"
	echo "$2  $f" | sha256sum -c --quiet
}
fetch https://ftp.gnu.org/gnu/binutils/binutils-2.45.tar.xz c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2
fetch https://ftp.gnu.org/gnu/gcc/gcc-6.5.0/gcc-6.5.0.tar.xz 7ef1796ce497e89479183702635b14bb7a46b53249209a5e0f999bebf4740945
fetch https://sourceware.org/pub/newlib/newlib-4.5.0.20241231.tar.gz 33f12605e0054965996c25c1382b3e463b0af91799001f5bb8c0630f2ec8c852
fetch https://gcc.gnu.org/pub/gcc/infrastructure/gmp-6.1.0.tar.bz2 498449a994efeba527885c10405993427995d3f86b8768d8cdf8d9dd7c6b73e8
fetch https://gcc.gnu.org/pub/gcc/infrastructure/mpfr-3.1.4.tar.bz2 d3103a80cdad2407ed581f3618c4bed04e0c92d1cf771a65ead662cc397f7775
fetch https://gcc.gnu.org/pub/gcc/infrastructure/mpc-1.0.3.tar.gz 617decc6ea09889fb08ede330917a00b16809b8db88c29c31bfbb49cbf88ecc3
cd "$W"
[[ -d binutils-2.45 ]] || tar xf binutils-2.45.tar.xz
if [[ ! -d gcc-6.5.0 ]]; then
	tar xf gcc-6.5.0.tar.xz --exclude=gcc-6.5.0/gcc/testsuite --exclude=gcc-6.5.0/libgo \
		--exclude=gcc-6.5.0/gotools --exclude=gcc-6.5.0/libjava --exclude=gcc-6.5.0/gcc/ada \
		--exclude=gcc-6.5.0/libstdc++-v3 --exclude=gcc-6.5.0/libsanitizer
	tar xf gmp-6.1.0.tar.bz2 && mv gmp-6.1.0 gcc-6.5.0/gmp
	tar xf mpfr-3.1.4.tar.bz2 && mv mpfr-3.1.4 gcc-6.5.0/mpfr
	tar xf mpc-1.0.3.tar.gz && mv mpc-1.0.3 gcc-6.5.0/mpc
	# no DWARF unwinder (and no emutls) in libgcc, see above
	sed -i -e '/^LIB2ADDEH = \$(srcdir)\/unwind-dw2.c/,/[^\\]$/c LIB2ADDEH =' \
		-e '/^LIB2ADDEH\(STATIC\|SHARED\)\? += \$(srcdir)\/emutls.c$/d' gcc-6.5.0/libgcc/Makefile.in
fi
[[ -d newlib-4.5.0.20241231 ]] || tar xf newlib-4.5.0.20241231.tar.gz
ln -sfn ../newlib-4.5.0.20241231/newlib gcc-6.5.0/newlib
ln -sfn ../newlib-4.5.0.20241231/libgloss gcc-6.5.0/libgloss
mkdir -p build-binutils build-gcc
(cd build-binutils && ../binutils-2.45/configure --target=mep-elf --prefix="$P" --disable-nls \
	--disable-werror --disable-gdb --disable-sim --disable-gprofng && make -j"$J" && make install)
export PATH=$P/bin:$PATH
(cd build-gcc && CFLAGS="-O2 -std=gnu99 -w" CXXFLAGS="-O2 -std=gnu++98 -fpermissive -w" \
	../gcc-6.5.0/configure --target=mep-elf --prefix="$P" --enable-obsolete --enable-languages=c \
	--with-newlib --disable-nls --disable-libssp --disable-shared --disable-threads \
	--disable-libquadmath --without-isl --disable-werror &&
	make -j"$J" MAKEINFO=true all-gcc all-target-libgcc all-target-newlib all-target-libgloss &&
	make MAKEINFO=true install-gcc install-target-libgcc install-target-newlib install-target-libgloss)
echo "toolchain in $P/bin; binutils build tree (BU_BUILD) in $W/build-binutils"
