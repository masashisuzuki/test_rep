/**
 * @file	aes256crypt.cpp
 * @brief	�Í���
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

// �p�X���[�h�Í����p�̃L�[
static const unsigned char s_identifier_info_key[32] =
{
	0xaa, 0xbb, 0xdd, 0xff, 0x00, 0x10, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00, 
	0x10, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xf0, 0xff, 0xff, 0xff, 0xff, 
};


/*
 * �e�X�g�R�[�h
 */
void Aes256Crypt::test()
{
	const std::wstring base_text = _T("�e�X�g�e�L�X�g");
	const std::vector<unsigned char> key(s_identifier_info_key, &s_identifier_info_key[32]);
	std::wstring encrypted_text;

	int result = EncryptString(base_text, key, encrypted_text);

	std::wstring decrypt_text;
	result = DecryptString(encrypted_text, key, decrypt_text);
	return;
}


/**
 * �������UTF8�֕ϊ�
 * @param[in] str		������
 * @retval std::string	UTF8������
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

	// ���݂̃f�[�^���N���A����
	bin.clear();
	// length�̃T�C�Y�ɂ���
	bin.resize(len);

	// �ݒ肷��f�[�^������ꍇ�̂݃R�s�[����
	if (len)
	{
		memcpy(&bin[0], data, len);
	}

	return true;
}


/**
*	std::vector<unsigned char>��binary�f�[�^�𖖔��ɒǉ�����
*	param[in]	bin		std::vector<unsigned char>
*	return		bool
*/
bool BackInsert(std::vector<unsigned char>& bin, const unsigned char* data, unsigned int len)
{
	if (! data)
		return false;

	// ���݂̃f�[�^����ێ�����
	size_t size = bin.size();
	// �ǉ����̃f�[�^�������Z����resize����
	bin.resize(size + len);

	// �ݒ肷��f�[�^������ꍇ�̂ݖ����ɃR�s�[����
	if (len)
	{
		memcpy(&bin[size], data, len);
	}

	return true;
}


/**
 *	std::vector<unsigned char>����Base64������𓾂�
 *	param[in]	bin	std::vector<unsigned char>
 *	param[out]	out std::wstring
 *	return		bool
 */
bool UbfbinaryToBase64(const std::vector<unsigned char> &bin, std::string &str)
{
	// std::vector<unsigned char>����ł���ꍇ�A����I���Ƃ��A�󕶎���Ԃ�
	if (bin.empty())
	{
		str.clear();
		return true;
	}

	try
	{
		// �G���R�[�h�����ꍇ�̃o�b�t�@���擾(�p�f�B���O����/���s�Ȃ�)
		int enclen = Base64EncodeGetRequiredLength(static_cast<int>(bin.size()), ATL_BASE64_FLAG_NOCRLF);
		// �ϊ���f�[�^�����O�̏ꍇ�́A�f�[�^�����Ă���\��������̂�Encode�����{���Ȃ�
		// ��ꂽ�f�[�^��Encode����Ɨp�ӂ����o�b�t�@��˂������ĕs���A�N�Z�X�ƂȂ鎖�����邽��
		if (enclen == 0)
		{
			return false;
		}

		std::vector<char> enc(enclen+1);
		// �G���R�[�h(�p�f�B���O����/���s�Ȃ�)
		Base64Encode(reinterpret_cast<BYTE*>(&(const_cast<std::vector<unsigned char>&>(bin).at(0))), 
						static_cast<int>(bin.size()), &enc[0], &enclen, ATL_BASE64_FLAG_NOCRLF);

		// �擾�����f�[�^��ݒ肷��
		str = &enc[0];
	}
	catch(...)
	{
		return false;
	}
	return true;
}

/**
 *	�}���`�o�C�g�����񂩂�std::wstring�𓾂�
 *	param[in]	str	�}���`�o�C�g������
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
 *	wstring����}���`�o�C�g������𓾂�
 *	param[in]	ubfstr	std::wstring
 *	return		�}���`�o�C�g������
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
		// Base64�f�R�[�h
		// �f�R�[�h�����ꍇ�̃o�b�t�@���擾
		int declen = Base64DecodeGetRequiredLength(static_cast<int>(str.length()));
		// �擾�����T�C�Y��std::vector<unsigned char>�̃T�C�Y��ύX����
		bin.resize(declen);
		// �f�R�[�h(std::vector<unsigned char>(=vector)�̗̈�͘A�����Ă��邱�Ƃ��ۏႳ��Ă���)
		Base64Decode(str.c_str(), static_cast<int>(str.length()), &bin.at(0), &declen);
		// �f�R�[�h��̃T�C�Y��std::vector<unsigned char>��؂�l�߂�
		bin.resize(declen);
	}
	catch(...)
	{
		return false;
	}
	return true;
}

/**
 *	Base64�����񂩂�std::vector<unsigned char>�𓾂�
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
 * UTF8�𕶎���֕ϊ�
 * @param[in] str		UTF8������
 * @retval std::wstring	������
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
 * AES-256-CBC �ňÍ�������
 * ������� UTF-8 �ɕϊ� �� �Í��� �� IV �ƘA������ Base64 �G���R�[�h �� UTF-16 �ɕϊ�
 * @param[in] plain ���͕�����i�󕶎���ł� OK�j
 * @param[in] key �Í����p�閧���i32�o�C�g�j
 * @param[out] encrypted �Í������ꂽ������iBase64�G���R�[�h�ς݁j
 */
int Aes256Crypt::EncryptString(const std::wstring& plain, const std::vector<unsigned char>& key, std::wstring& encrypted)
{
	unsigned char iv[EVP_MAX_IV_LENGTH];
	RAND_pseudo_bytes(iv, sizeof(iv));

	const EVP_CIPHER* cipher = EVP_aes_256_cbc();
	if (key.size() != cipher->key_len)
	{
		// invalid key length
		return -1;	// �������s��
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
 * AES-256-CBC �ŕ�������
 * Base64 �f�R�[�h �� IV �� �Í��������ɕ��� �� ���� �� UTF-16 �ɕϊ�
 * @param[in] plain ���͕�����i�󕶎���ł� OK�j
 * @param[in] key �Í����p�閧���i32�o�C�g�j
 * @param[out] encrypted �Í������ꂽ������iBase64�G���R�[�h�ς݁j
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


