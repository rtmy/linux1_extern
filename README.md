# linux1_extern

* filename is contained in inode  
* mkdir works like mkdir -p  

## TODO
* no writing if no file exists
* no ls if no dir
* makefile update
* mechanism for exception return to server  
* free space determinator, df -ah
* cp -r 

## Known bugs
* removal of original data removes copy data -- check how its copied

## Build
`set module_final.c FILESYSTEM const to where the fs should be`  
`make`

## Usage
### startup
`make test`, get nod number, then  
`sudo mknod /dev/module c <nod number> 0`  
`insmod module_final.ko`  
sudo `./server <port>`  
`./client <ip addr> <port>`  

### format
`./format.sh <filepath>`  
`any command in client`
