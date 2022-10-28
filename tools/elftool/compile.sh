gcc -fPIC -c lbc_syms.c -g
gcc -shared  -fPIC -o syms.so lbc_syms.o -lbfd
gcc dltest.c -o dltest -ldl