# linux1_extern

* filename is contained in inode  
* there is no cp -r  
* mkdir works like mkdir -p  

## TODO
* add words to client
* no writing if no file exists
* no ls if no dir
* makefile update
* exception return to server mechanism 
* free space determinator, df -ah

## Known bugs
* ls for empty dir -> gets Killed — check emptiness
* ls for nested dirs -> gets Killed — confirm to call ls on parent
* ls parent after rm — check residues during ls
* removal of original data removes copy data -- check how its copied

## Build
`set module_final.c FILESYSTEM const to where the fs should be`  
`make`

## Usage
### startup
`make test`, get nod number, then  
`sudo mknod /dev/module c <nod number> 0`  
`insmod module_final.ko`  
`./server <port>`  
`./client <ip addr> <port>`  

### format
`./format.sh <filepath>`  
`any command in client`
