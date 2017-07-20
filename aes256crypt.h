/**
 * @file	Aes256Crypt.h
 * @brief	à√çÜâª
 *
 */

#ifndef AES256_CRYPT_H_
#define AES256_CRYPT_H_

#include <string>
#include <vector>


class Aes256Crypt
{
public:
	static void test();

	static int EncryptString(const std::wstring& plain, const std::vector<unsigned char>& key, std::wstring& encrypted);
	static int DecryptString(const std::wstring& encrypted, const std::vector<unsigned char>& key, std::wstring& decrypted);
};


#endif
