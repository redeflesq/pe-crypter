# Portable Executable Crypter
Its an exe stub-crypter which will encrypt(by xor encryption your PE exe input file and add it as overlay to the end of the output new exe file(stub).  
The key and separator between stub and encrypted data will be generated randomly.  
In theory, it should work with both 32-bit and 64-bit applications, but in practice it has not been tested.  

# How to use
Crypter has two modes of operation, the first is to simply transfer the file to the cryptor or give it the path to the file on the command line, the second mode of operation is described in the code