/**
 * @file	aes256crypt.cpp
 * @brief	暗号化
 *
 */

#include "stdafx.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atlenc.h>
#include "aes256crypt.h"

#ifdef _DEBUG
	#pragma comment(lib, "libeay32d.lib")
#else
	#pragma comment(lib, "libeay32.lib")
#endif

// パスワード暗号化用のキー
static const unsigned char s_identifier_info_key[32] =
{
	0xaa, 0xbb, 0xdd, 0xff, 0x00, 0x10, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 
	0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf0, 0xff, 0xff, 0xff, 0xff, 
};


/*
 * テストコード
 */
void Aes256Crypt::test()
{
	const std::wstring base_text = _T("テストテキスト");
	const std::vector<unsigned char> key(s_identifier_info_key, &s_identifier_info_key[32]);
	std::wstring encrypted_text;

	int result = EncryptString(base_text, key, encrypted_text);

	std::wstring decrypt_text;
	result = DecryptString(encrypted_text, key, decrypt_text);
	return;
}


/**
 * 文字列をUTF8へ変換
 * @param[in] str		文字列
 * @retval std::string	UTF8文字列
 */
std::string	ubfstring2utf8string(const std::wstring &str)
{
	const int nLength = ::WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), NULL, 0, NULL, NULL);
	if (nLength)
	{
		char *pWork = new char [nLength];
		if (pWork)
		{
			::WideCharToMultiByte(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), pWork, nLength, NULL, NULL);
			const std::string ret = std::string(pWork, nLength);
			delete[] pWork;
			return ret;
		}
	}
	return std::string();
}

bool SetData(std::vector<unsigned char>& bin, const void* data, size_t len)
{
	if (! data)
		return false;

	// 現在のデータをクリアする
	bin.clear();
	// lengthのサイズにする
	bin.resize(len);

	// 設定するデータがある場合のみコピーする
	if (len)
	{
		memcpy(&bin[0], data, len);
	}

	return true;
}


/**
*	std::vector<unsigned char>にbinaryデータを末尾に追加する
*	param[in]	bin		std::vector<unsigned char>
*	return		bool
*/
bool BackInsert(std::vector<unsigned char>& bin, const unsigned char* data, unsigned int len)
{
	if (! data)
		return false;

	// 現在のデータ長を保持する
	size_t size = bin.size();
	// 追加分のデータ長を加算してresizeする
	bin.resize(size + len);

	// 設定するデータがある場合のみ末尾にコピーする
	if (len)
	{
		memcpy(&bin[size], data, len);
	}

	return true;
}


/**
 *	std::vector<unsigned char>からBase64文字列を得る
 *	param[in]	bin	std::vector<unsigned char>
 *	param[out]	out std::wstring
 *	return		bool
 */
bool UbfbinaryToBase64(const std::vector<unsigned char> &bin, std::string &str)
{
	// std::vector<unsigned char>が空である場合、正常終了とし、空文字を返す
	if (bin.empty())
	{
		str.clear();
		return true;
	}

	try
	{
		// エンコードした場合のバッファ長取得(パディングあり/改行なし)
		int enclen = Base64EncodeGetRequiredLength(static_cast<int>(bin.size()), ATL_BASE64_FLAG_NOCRLF);
		// 変換後データ長が０の場合は、データが壊れている可能性があるのでEncodeを実施しない
		// 壊れたデータをEncodeすると用意したバッファを突き抜けて不正アクセスとなる事があるため
		if (enclen == 0)
		{
			return false;
		}

		std::vector<char> enc(enclen+1);
		// エンコード(パディングあり/改行なし)
		Base64Encode(reinterpret_cast<BYTE*>(&(const_cast<std::vector<unsigned char>&>(bin).at(0))), 
						static_cast<int>(bin.size()), &enc[0], &enclen, ATL_BASE64_FLAG_NOCRLF);

		// 取得したデータを設定する
		str = &enc[0];
	}
	catch(...)
	{
		return false;
	}
	return true;
}

/**
 *	マルチバイト文字列からstd::wstringを得る
 *	param[in]	str	マルチバイト文字列
 *	return		std::wstring
 */
std::wstring string2ubfstring(const std::string &str)
{
	int	buflen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);

	if(buflen)
	{
		std::vector<wchar_t> dest(buflen);
		buflen = ::MultiByteToWideChar(CP_ACP, 0, str.c_str(), static_cast<int>(str.length()), &dest[0], buflen);
		if(buflen)
		{
			return std::wstring(dest.begin(), dest.begin() + buflen);
		}
	}
	return _T("");
}


/**
 *	wstringからマルチバイト文字列を得る
 *	param[in]	ubfstr	std::wstring
 *	return		マルチバイト文字列
 */
std::string	ubfstring2string(const std::wstring &ubfstr)
{
	int	buflen = ::WideCharToMultiByte(CP_ACP, 0, ubfstr.c_str(), 
					static_cast<int>(ubfstr.size()), NULL, 0, NULL, NULL);

	if (buflen)
	{
		std::vector<char> dest(buflen);
		buflen = ::WideCharToMultiByte(CP_ACP, 0, ubfstr.c_str(), 
					static_cast<int>(ubfstr.size()), &dest[0], buflen, NULL, NULL);
		if (buflen)
		{
			return std::string(dest.begin(), dest.begin() + buflen);
		}
	}
	return "";
}


bool Base64ToUbfbinary(const std::string &str, std::vector<unsigned char> &bin)
{
	try
	{
		// Base64デコード
		// デコードした場合のバッファ長取得
		int declen = Base64DecodeGetRequiredLength(static_cast<int>(str.length()));
		// 取得したサイズでstd::vector<unsigned char>のサイズを変更する
		bin.resize(declen);
		// デコード(std::vector<unsigned char>(=vector)の領域は連続していることが保障されている)
		Base64Decode(str.c_str(), static_cast<int>(str.length()), &bin.at(0), &declen);
		// デコード後のサイズにstd::vector<unsigned char>を切り詰める
		bin.resize(declen);
	}
	catch(...)
	{
		return false;
	}
	return true;
}

/**
 *	Base64文字列からstd::vector<unsigned char>を得る
 *	param[in]	in	std::wstring
 *	param[out]	bin ubfbinaly
 *	return		bool
 */
bool Base64ToUbfbinary(const std::wstring &str, std::vector<unsigned char> &bin)
{
	std::string mstr = ubfstring2string(const_cast<std::wstring&>(str));
	return Base64ToUbfbinary(mstr, bin);
}


/**
 * UTF8を文字列へ変換
 * @param[in] str		UTF8文字列
 * @retval std::wstring	文字列
 */
std::wstring utf8string2ubfstring(const std::string &str)
{
	const int nLength = ::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), NULL, 0);
	if (nLength)
	{
		TCHAR *pWork = new TCHAR [nLength];
		if (pWork)
		{
			::MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.length()), pWork, nLength);
			const std::wstring ret = std::wstring(pWork, nLength);
			delete[] pWork;
			return ret;
		}
	}
	return std::wstring();
}

/**
 * AES-256-CBC で暗号化する
 * 文字列を UTF-8 に変換 → 暗号化 → IV と連結して Base64 エンコード → UTF-16 に変換
 * @param[in] plain 入力文字列（空文字列でも OK）
 * @param[in] key 暗号化用秘密鍵（32バイト）
 * @param[out] encrypted 暗号化された文字列（Base64エンコード済み）
 */
int Aes256Crypt::EncryptString(const std::wstring& plain, const std::vector<unsigned char>& key, std::wstring& encrypted)
{
	unsigned char iv[EVP_MAX_IV_LENGTH];
	RAND_pseudo_bytes(iv, sizeof(iv));

	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	if (key.size() != cipher->key_len)
	{
		// invalid key length
		return -1;	// 引数が不正
	}

	EVP_CIPHER_CTX ctx;
	EVP_EncryptInit(&ctx, cipher, &key[0], iv);

	std::vector<unsigned char> buf;
	int olen, tmp;
	std::string utf8 = ubfstring2utf8string(plain);
	buf.resize(utf8.size() + EVP_CIPHER_CTX_block_size(&ctx));
	EVP_EncryptUpdate(&ctx, &buf[0], &olen, reinterpret_cast<unsigned char*>(&utf8[0]), static_cast<int>(utf8.size()));
	EVP_EncryptFinal(&ctx, &buf[olen], &tmp);
	EVP_CIPHER_CTX_cleanup(&ctx);
	olen += tmp;

	std::vector<unsigned char> cryptbin;
	SetData(cryptbin, iv, EVP_MAX_IV_LENGTH);
	BackInsert(cryptbin, &buf[0], olen);

	std::string cryptstr;
	UbfbinaryToBase64(cryptbin, cryptstr);
	encrypted = string2ubfstring(cryptstr);

	return 0;
}


/**
 * AES-256-CBC で復号する
 * Base64 デコード → IV と 暗号化部分に分離 → 復号 → UTF-16 に変換
 * @param[in] plain 入力文字列（空文字列でも OK）
 * @param[in] key 暗号化用秘密鍵（32バイト）
 * @param[out] encrypted 暗号化された文字列（Base64エンコード済み）
 */
int Aes256Crypt::DecryptString(const std::wstring& encrypted, const std::vector<unsigned char>& key, std::wstring& decrypted)
{
	std::vector<unsigned char> cryptbin;
	Base64ToUbfbinary(encrypted, cryptbin);

	if (cryptbin.size() <= EVP_MAX_IV_LENGTH)
	{
		return -1;
	}
	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	if (key.size() != cipher->key_len)
	{
		// invalid key length
		return -1;
	}

	EVP_CIPHER_CTX ctx;
	EVP_DecryptInit(&ctx, cipher, &key[0], &cryptbin[0]);

	int olen, tmp;
	std::string utf8;
	utf8.resize(cryptbin.size());
	unsigned char* p = reinterpret_cast<unsigned char*>(&utf8[0]);
	EVP_DecryptUpdate(&ctx, p, &olen, &cryptbin[EVP_MAX_IV_LENGTH], static_cast<int>(cryptbin.size()) - EVP_MAX_IV_LENGTH);
	EVP_DecryptFinal(&ctx, p + olen, &tmp);
	EVP_CIPHER_CTX_cleanup(&ctx);
	olen += tmp;
	utf8.resize(olen);
	decrypted = utf8string2ubfstring(utf8);

	return 0;
}


