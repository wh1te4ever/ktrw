#!/bin/zsh
rm ./kernelcache.iPhone10,1.18D70;

pzb -d -g kernelcache.release.iphone10 https://updates.cdn-apple.com/2021WinterFCS/fullrestores/071-23198/C10D1954-77D2-4340-B0B3-17EFD3ED957B/iPhone_4.7_P3_14.4.2_18D70_Restore.ipsw;
wget https://github.com/excitedplus1s/jtool2/raw/refs/heads/main/jtool2;
chmod +x jtool2;
./jtool2 -dec ./kernelcache.release.iphone10;
mv /tmp/kernel ./kernelcache.iPhone10,1.18D70

rm jtool2;
rm ./kernelcache.release.iphone10;