[whats?]  
A project to make it easy to build xerub's de rebus antiquis [https://xerub.github.io/ios/iboot/2018/05/10/de-rebus-antiquis.html].  

[how to use]  
* build nettoyeur  
cd target/  
arm-none-eabi-gcc -c -Os nettoyeur.c  
arm-none-eabi-objcopy -O binary nettoyeur.o nettoyeur  

*build make_rdskF 
gcc make_rdskF.c lzss.c -o make_rdskF  

*run  
./make_rdsk3 target/ramdisk.dmg target/ramdisk3.dmg  
./make_rdskF target/ramdisk3.dmg target/ramdiskF.dmg target/nettoyeur  