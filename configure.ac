AC_INIT

AC_CONFIG_MACRO_DIRS([m4/])

AC_CANONICAL_BUILD
AC_CANONICAL_HOST

AC_PROG_INSTALL

AC_PROG_CC
LCRUST_PROG_RUSTC

features=

AC_ARG_ENABLE(sha3,[Enable use of sha3 algorithms for password security],[
    features="${features} sha3"
])

AC_ARG_ENABLE(blake2,[Enable use of blake2 algorithms for password security],[
    features="${features} blake2"
])

AC_ARG_ENABLE(sha512_t,[Enable use of sha512/224 and sha512/256 algorithms for password security],[
    features="${features} sha512_t"
])



AC_OUTPUT