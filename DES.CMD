cl -c -G2s -W3 des.c
cl -c -G2s -W3 tables.c
cl -c -G2s -W3 main.c

link main+des+tables

rename main.exe des.exe
erase main.exe
erase main.obj

