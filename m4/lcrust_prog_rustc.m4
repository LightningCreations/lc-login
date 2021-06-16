
AC_DEFUN([LCRUST_PROG_RUSTC],[
    AC_REQUIRE([AC_PROG_CC])
    AC_REQUIRE([AC_CANONICAL_HOST])
    AC_ARG_VAR(RUSTC,[Rust compiler to use])
    AC_ARG_VAR(RUSTFLAGS,[Flags to pass to the rust compiler])


    if test x$host_alias != x 
    then
        AC_PATH_PROGS(RUSTC,[rustc lcrustc $host-gccrs])
    else 
        AC_PATH_PROGS(RUSTC,[rustc lcrustc $host-gccrs gccrs])
    fi

    if test "$RUSTC" \= ""
    then
        AC_MSG_ERROR([Failed to find a rust compiler. Install rustc in PATH, or set RUSTC to a suitable compiler])
    fi

    if test x$host_alias != x
    then
        case $RUSTC in 
            *[\\/]$host-* ) dnl gccrs has a host prefix when cross-compiling, so no need to attempt using `--target`
                ;;
            * )
                SAVE_RUSTFLAGS="$RUSTFLAGS"
                AC_MSG_CHECKING([how to cross compile with $RUSTC])
                RUSTFLAGS="$RUSTFLAGS --target $host"
                echo '' > test.rs
                $RUSTC $RUSTFLAGS --crate-type rlib --crate-name test test.rs 2>> config.log > /dev/null
                
                if test $? -eq 0
                then
                    AC_MSG_RESULT([--target $host])
                else
                    rm -f test.rs libtest.rlib
                    RUSTFLAGS="$SAVE_RUSTFLAGS --target $host_alias"
                    echo '' > test.rs
                    $RUSTC $RUSTFLAGS --crate-type rlib --crate-name test test.rs  2>> config.log > /dev/null
                    if test $? -eq 0
                    then
                        rm -f test.rs libtest.rlib
                        AC_MSG_RESULT([--target $host_alias])
                    else
                        rm -f test.rs libtest.rlib
                        case "$host" in 
                            x86_64-pc-*-* )
                                IFS="-" read arch vendor kernel env  <<< "$host"
                                host_target="$arch-unknown-$kernel-$env"
                                RUSTFLAGS="$SAVE_RUSTFLAGS --target $host_target"
                                echo '' > test.rs
                                $RUSTC $RUSTFLAGS --crate-type rlib --crate-name test test.rs  2>> config.log > /dev/null
                                if test $? -eq 0
                                then
                                    rm -f test.rs libtest.rlib
                                    AC_MSG_RESULT([--target $host_target])
                                else
                                    AC_MSG_RESULT([failed])
                                    AC_MSG_ERROR([Cannot determine how to cross compile to $host with $RUSTC])
                                fi
                            ;;

                            i?86-pc-*-* )
                                IFS="-" read arch vendor kernel env  <<< "$host"
                                host_target="$arch-unknown-$kernel-$env"
                                RUSTFLAGS="$SAVE_RUSTFLAGS --target $host_target"
                                echo '' > test.rs
                                $RUSTC $RUSTFLAGS --crate-type rlib --crate-name test test.rs  2>> config.log > /dev/null
                                if test $? -eq 0
                                then
                                    rm -f test.rs libtest.rlib
                                    AC_MSG_RESULT([--target $host_target])
                                else
                                    AC_MSG_RESULT([failed])
                                    AC_MSG_ERROR([Cannot determine how to cross compile to $host with $RUSTC])
                                fi
                            ;;

                            *)
                                AC_MSG_RESULT([failed])
                                AC_MSG_ERROR([Cannot determine how to cross compile to $host with $RUSTC])
                                ;;
                        esac
                    fi
                fi
                ;;
        esac
    fi

    AC_MSG_CHECKING([whether Rust compiler works])
    echo 'fn main(){}' > test.rs 
    $RUSTC $RUSTFLAGS --crate-type bin --crate-name test test.rs 2>> config.log > /dev/null
    if test $? -ne 0
    then
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([Cannot compile a simple program with $RUSTC])
    fi

    if test x$host_alias != x 
    then
        ./test${EXEEXT}
        if test $? -ne 0
        then
            AC_MSG_RESULT([no])
            AC_MSG_ERROR([Cannot compile a simple program with $RUSTC])
        fi
    fi

    rm -rf test.rs test${EXEEXT}

    AC_MSG_RESULT([yes])

    AC_SUBST(RUSTC)
    AC_SUBST(RUSTFLAGS)
])
