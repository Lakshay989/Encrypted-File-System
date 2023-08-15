# Encrypted Filesystem

The purpose of the project is to implement an encrypted filesystem using the [fusepy library](https://github.com/fusepy/fusepy), which allows users to write filesystems with encryption completely in user space. 

Example usage:

```
#just do this stuff once:
mkdir encrypted mountpoint #make folders for the physical + encrypted FSs
cp testFile encrypted/testFile #put the test file I gave you in the physical FS

#to test your code:
/opt/homebrew/bin/python3 encfsStarterCode.py encrypted mountpoint   #encrypted is the physical filesystem, mountpoint is the virtual filesystem
enter the password which is just password

#lots of spam from FUSE logger
```
 

In another terminal:

```
$ cat mountpoint/testFile 
hello
#reading from the virtual filesystem opens the encrypted version 
#from the physical filesystem, and decrypts the contents for us

#make your own encrypted file
$ echo hello > mountpoint/somefile  
#writing plaintext to the virtual filesystem.  
#the FS stores the encrypted version in the physical filesystem



# this is the only data that's stored on disk.  It's in the physical filesystem and is encrypted
$ cat encrypted/hello 
B���t���]��b����gAAAAABaxTxhrkpLlcm5wm22dbaUYkMaKEHVXKEKiMAq17uQAg1UVlYQkJEjtZc5kQ0DbEjVrotMtCaIw7kuW4Li3sqfA8_8TQ==% 
``` 

If Ctrl-C doesn't seem to reliably kill the python script, you can kill it (I think safely) from another terminal by running `umount <path to your decrypted view mountpoint, so "mountpoint" in the examble above>`
 
