#!/bin/bash
# Runs INSIDE the lab container. Builds libpng (as mounted, possibly patched)
# with ASan+UBSan, builds a one-shot harness, and runs the proof-of-vuln blob.
#
# MODE:
#   prove   build + run the blob; expect a sanitizer abort (the bug is live)
#   verify  build + run the blob (expect NO abort) + run libpng's self-test
#
# Exit codes: 0 = gate PASSED for the given mode, non-zero = FAILED/error.
set -u
SRC=/work/target
BLOB="$SRC/.aixcc/vulns/vuln_0/blobs/sample_data.bin"
MODE="${1:-prove}"
export CC=clang CXX=clang++
SAN="-fsanitize=address,undefined -fno-omit-frame-pointer"
export CFLAGS="-g -O1 $SAN"
export CXXFLAGS="-g -O1 $SAN"
export ASAN_OPTIONS=abort_on_error=0:exitcode=99:detect_leaks=0
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1

cd "$SRC" || exit 3

echo "[build] configuring + building libpng with ASan/UBSan..."
if [ ! -f Makefile ]; then
  ./configure --disable-shared >/work/configure.log 2>&1 \
    || { echo "[build] configure FAILED"; tail -25 /work/configure.log; exit 3; }
fi
make -j"$(nproc)" libpng16.la >/work/make.log 2>&1 \
  || { echo "[build] libpng build FAILED"; tail -40 /work/make.log; exit 3; }

echo "[build] linking one-shot harness..."
clang -c $CFLAGS /work/oneshot_driver.c -o /work/driver.o 2>/work/link.log \
  || { echo "[build] driver compile FAILED"; cat /work/link.log; exit 3; }
clang++ $CXXFLAGS -I. \
  contrib/oss-fuzz/libpng_read_fuzzer.cc /work/driver.o \
  .libs/libpng16.a -lz -o /work/pngfuzz_oneshot 2>>/work/link.log \
  || { echo "[build] harness link FAILED"; tail -40 /work/link.log; exit 3; }

run_pov() {
  echo "[pov] replaying $(basename "$BLOB") under ASan/UBSan..."
  /work/pngfuzz_oneshot "$BLOB"
  return $?
}

case "$MODE" in
  prove)
    run_pov; rc=$?
    echo "[pov] harness exit code: $rc"
    if [ "$rc" -eq 99 ] || [ "$rc" -ge 128 ]; then
      echo "[GATE prove] PASS -- sanitizer caught the vulnerability (bug is live)."
      exit 0
    else
      echo "[GATE prove] FAIL -- no sanitizer abort; expected a crash here."
      exit 1
    fi
    ;;
  verify)
    run_pov; rc=$?
    echo "[pov] harness exit code: $rc"
    if [ "$rc" -eq 99 ] || [ "$rc" -ge 128 ]; then
      echo "[GATE verify] FAIL -- patch did NOT stop the crash (still vulnerable)."
      exit 1
    fi
    echo "[pov] no crash on the PoV -- good. Now running libpng self-test..."
    if make test >/work/test.log 2>&1; then
      echo "[GATE verify] PASS -- PoV no longer crashes AND the test suite passes."
      exit 0
    else
      echo "[GATE verify] FAIL -- PoV fixed but the patch broke the test suite:"
      tail -25 /work/test.log
      exit 1
    fi
    ;;
  *)
    echo "unknown MODE: $MODE (use prove|verify)"; exit 2 ;;
esac
