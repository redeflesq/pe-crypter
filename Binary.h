#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>

int GetFileSizeFp(FILE* file);
int ReadBinaryFile(char* file, char** buf);
int FindStringInBinaryFile(char* bin, int bin_size, char* find, int find_size, int count);
int WriteBinaryFile(char* file, char* data, int size);
void XORBinary(char* bin, int bin_size, char* key, int key_size);