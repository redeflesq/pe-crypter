#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <sys/stat.h>   // stat
#include <time.h>
#include "Binary.h"

/* CHANGE THIS */
#define STUB_NAME "XorCrypterStubRelease.exe"
#define STUB_DEFAULT_KEY "oUf!rOsj6x*FgyNjBuTuW#R0jZSOg!kD1D8ZYc$YDZbgiXaoxVS@xCOW%y%sdVES"
#define STUB_DEFAULT_SEPARATOR "mxE98lDhF6mGxJd6"
/* CNAHGE THIS  */

#define EWHILE(s) while(s){}0
#define MAX_STRING_SIZE 512

#define PLINE() "\t--------------------------------------------------------------"
#define PERROR(s) "\t[Error] " s
#define PINFO(s) "\t[Info] " s
#define PACTION(s) "\t[+] " s

int FileExist(const char* filename) {
	struct stat   buffer;
	return (stat(filename, &buffer) == 0);
}

int GetStringLen(char* str)
{
	int i = 0;
	EWHILE(str[i++] != '\0');
	return i - 2;
}

#define ASCII_START 32
#define ASCII_END 126

char* GenerateRandomString(int size) {
	srand(time(NULL) + size);
	int i;
	char* res = malloc(size + 1);
	for (i = 0; i < size; i++) {
		res[i] = (char)(rand() % (ASCII_END - ASCII_START)) + ASCII_START;
	}
	res[i] = '\0';
	return res;
}

void ReadLine(const char* msg, char** buf)
{
	char* line = (char*)malloc(MAX_STRING_SIZE * sizeof(char));
	printf("%s: ", msg);

	if (line) {
		fgets(line, MAX_STRING_SIZE, stdin);
	} else {
		goto exit;
	}

	int size = GetStringLen(line);//change
	if (!size) {
		goto exit;
	}

	*buf = (char*)malloc((size+1) * sizeof(char));

	if (!*buf) {
		goto exit;
	}

	for (int i = 0; i < size; i++)
	{
		*(*buf + i) = line[i];
	}

	*(*buf + size) = '\0';

	exit:
	free(line);
}

int CheckExtFile(char* line)
{
	int len = strlen(line);

	if (!(len > 4 &&
		line[len - 1] == 'e' &&
		line[len - 2] == 'x' &&
		line[len - 3] == 'e' &&
		line[len - 4] == '.')) {
		return 0;
	}

	return 1;
}

void cryptfile(char* input, char* output)
{
	char* m_sStubData;
	int m_iStubSize = ReadBinaryFile(STUB_NAME, &m_sStubData);

	printf("%s: %d\n", PINFO("[Stub] File size"), m_iStubSize);
	
	//INSERT NEW KEY
	char* m_sKey = STUB_DEFAULT_KEY;
	char* m_sNewXorKey;
	int m_iKeyLen = strlen(m_sKey);
	{
		
		int m_iKeyPos = FindStringInBinaryFile(m_sStubData, m_iStubSize, m_sKey, m_iKeyLen, 0);

		printf("%s: %d\n", PINFO("[Stub] XOR key position start"), m_iKeyPos);
		printf("%s: %d\n", PINFO("[Stub] XOR key position end"), m_iKeyPos + m_iKeyLen);

		m_sNewXorKey = GenerateRandomString(m_iKeyLen);

		printf("%s: '%s'\n", PINFO("[Stub] Insert new key"), m_sNewXorKey);

		for (int i = 0; i < m_iKeyLen; i++)
		{
			*(m_sStubData + m_iKeyPos + i) = *(m_sNewXorKey + i);
		}
	}

	//INSERT NEW SEPARATOR
	char* m_sSeparator = STUB_DEFAULT_SEPARATOR;
	char* m_sNewSeparator;
	int m_iSeparatorLen = strlen(m_sSeparator);
	{
		int m_iSeparatorPos = FindStringInBinaryFile(m_sStubData, m_iStubSize, m_sSeparator, m_iSeparatorLen, 0);

		printf("%s: %d\n", PINFO("[Stub] Separator position start"), m_iSeparatorPos);
		printf("%s: %d\n", PINFO("[Stub] Separator position end"), m_iSeparatorPos + m_iSeparatorLen);

		m_sNewSeparator = GenerateRandomString(m_iSeparatorLen);

		printf("%s: '%s'\n", PINFO("[Stub] Insert new separator"), m_sNewSeparator);

		for (int i = 0; i < m_iSeparatorLen; i++)
		{
			*(m_sStubData + m_iSeparatorPos + i) = *(m_sNewSeparator + i);
		}
	}

	
	char* m_sInputData;
	int m_iInputSize = ReadBinaryFile(input, &m_sInputData);

	XORBinary(m_sInputData, m_iInputSize, m_sNewXorKey, m_iKeyLen);

	printf("%s: %dB\n", PINFO("Input file size"), m_iInputSize);

	int m_iOutputSize = m_iStubSize + m_iSeparatorLen + m_iInputSize;
	char* m_sOutputData = (char*)malloc(m_iOutputSize * sizeof(char));

	int j = 0;

	for (int i = 0; i < m_iStubSize; i++)
	{
		*(m_sOutputData + j++) = *(m_sStubData + i);
	}

	for (int i = 0; i < m_iSeparatorLen; i++)
	{
		*(m_sOutputData + j++) = *(m_sNewSeparator + i);
	}

	for (int i = 0; i < m_iInputSize; i++)
	{
		*(m_sOutputData + j++) = *(m_sInputData + i);
	}

	printf("%s: %dB\n", PINFO("Total write bytes"), j);

	WriteBinaryFile(output, m_sOutputData, m_iOutputSize);

	printf("%s: %dB\n", PINFO("Output file size"), m_iOutputSize);

	free(m_sStubData);
	free(m_sInputData);
	free(m_sOutputData);
	free(m_sNewXorKey);
	free(m_sNewSeparator);
exit:
	return;
}

int main(int a, char** args)
{
	printf("\n\n\n\n%s\n%s\n%s\n%s\n%s\n",
		PINFO("XORCrypter 0.1"),
		PINFO(__TIMESTAMP__),
		PLINE(),
		PINFO("Example Input\\Output File: \"example.exe\""),
		PLINE()
	);

	if (!FileExist(STUB_NAME)) {
		printf("%s\n", PERROR("Stub doesn't exist"));
		return 0;
	}

	char* m_sInputFileName;
	char* m_sOutputFileName;
	ReadLine("\t[+] Input filename", &m_sInputFileName);
	ReadLine("\t[+] Output filename", &m_sOutputFileName);

	printf("%s\n", PLINE());

	if (strcmp(m_sInputFileName, m_sOutputFileName) == 0) {
		printf("%s\n", PERROR("Input and output file name is equal"));
		goto exit;
	}

	if (!CheckExtFile(m_sInputFileName) || !CheckExtFile(m_sOutputFileName)) {
		printf("%s\n", PERROR("Input\\Output extension is invalid"));
		goto exit;
	}

	if (!FileExist(m_sInputFileName)) {
		printf("%s '%s' %s\n", PERROR("Input file"), m_sInputFileName, "doesn't exist");
		goto exit;
	}

	if (FileExist(m_sOutputFileName)) {
		printf("%s '%s' %s\n", PERROR("Output file"), m_sOutputFileName, "is already exist");
		goto exit;
	}

	cryptfile(m_sInputFileName, m_sOutputFileName);

	printf("%s\n", PINFO("File successfuly crypted"));
	
exit:
	free(m_sInputFileName);
	free(m_sOutputFileName);

	return 0;
}