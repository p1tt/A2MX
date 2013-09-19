#include "crypto.h"

static SecByteBlock str2sb(std::string data) {
	return SecByteBlock((byte*)data.data(), data.size());
}
static std::string sb2str(SecByteBlock data) {
	return std::string((char*)data.data(), data.size());
}

Crypto::Crypto(std::string der_keyfile_address, std::string der_keyfile_sign, std::string der_keyfile_encrypt) {
	m_a2mxcrypto = new A2MXcrypto(der_keyfile_address, der_keyfile_sign, der_keyfile_encrypt);
}

Crypto::Crypto(std::string keyfilepath, std::string password) {
	m_a2mxcrypto = new A2MXcrypto(keyfilepath, str2sb(password));
}

Crypto::Crypto(std::string pubkey) {
	m_a2mxcrypto = new A2MXcrypto(str2sb(pubkey), A2MXcrypto::pubkeyDataType::Auto);
}

Crypto::~Crypto() {
	if (m_a2mxcrypto != 0)
		delete m_a2mxcrypto;
}

std::string Crypto::pubkeyHash() {
	return sb2str(m_a2mxcrypto->pubkeyHash());
}

std::string Crypto::pubkeyHashBase58() {
	return m_a2mxcrypto->pubkeyHashBase58();
}

std::string Crypto::pubkeyData() {
	return sb2str(m_a2mxcrypto->pubkeyData());
}

std::string Crypto::pubkeyAddress() {
	return sb2str(m_a2mxcrypto->pubkeyCompressed(m_a2mxcrypto->pubkeyAddress()));
}

std::string Crypto::signAddress(std::string message) {
	return sb2str(m_a2mxcrypto->signAddress(str2sb(message)));
}

bool Crypto::verifyAddress(std::string message, std::string signature) {
	return m_a2mxcrypto->verifyAddress(str2sb(message), str2sb(signature));
}

std::string Crypto::sign(std::string message) {
	return sb2str(m_a2mxcrypto->sign(str2sb(message)));
}

bool Crypto::verify(std::string message, std::string signature) {
	return m_a2mxcrypto->verify(str2sb(message), str2sb(signature));
}

std::string Crypto::encrypt(std::string data) {
	return sb2str(m_a2mxcrypto->encrypt(str2sb(data)));
}

std::string Crypto::decrypt(std::string data) {
	if (m_a2mxcrypto == 0)
		throw A2MXcrypto::Error("Cannot decrypt without private key");
	return sb2str(m_a2mxcrypto->decrypt(str2sb(data)));
}

void Crypto::createNewKeyFile(const std::string& keyfilepath, std::string password) {
	A2MXcrypto::createNewKeyFile(keyfilepath, str2sb(password));
}

