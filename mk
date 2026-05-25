rm -f b.exe
x86_64-w64-mingw32-dlltool -k -d /home/ubuntu/wine/dlls/propsys/libpropsys.def -l libpropsys.a
#x86_64-w64-mingw32-g++ -g -I./wdk-10/Include/wdf/umdf/1.11 -I./wdk-10/Include/10.0.10586.0/shared/ -I./wdk-10/Include/10.0.10586.0/um -I./wdk-10/Include/10.0.10586.0/km -I./wdk-10/Include/10.0.10586.0/mmos -Wall hello.cc breakpoints.c -luuid -lole32 -L. -lpropsys
x86_64-w64-mingw32-g++ -Wl,--stack,32000000 -g3 -I./wdk-10/Include/wdf/umdf/1.11 -I. -Wall hello.cc breakpoints.c -luuid -lole32 -L. -lpropsys -lsetupapi -lwinusb -lcfgmgr32 -o b.exe

ls -la b.exe
