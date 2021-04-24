# linux1_extern

## Build
`make`

## Usage
### startup
`make test`, get nod number, then  
`insmod module_final.ko`  
`./server <port>`  
`./client <ip addr> <port>`  

### format
`dd if=/dev/zero of=<filepath> bs=1M count=32`  
`any command in client`

## Details
Filename is contained in inode.

## TODO module
* rm
* nested dirs

## TODO project
* makefile update

## TODO
* format tool
* free space determinator, df -ah
