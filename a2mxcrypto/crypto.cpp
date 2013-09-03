#include "crypto.h"

static SecByteBlock str2sb(std::string data) {
	return SecByteBlock((byte*)data.data(), data.size());
}
static std::string sb2str(SecByteBlock data) {
	return std::string((char*)data.data(), data.size());
}

Crypto::Crypto(std::string keyfilepath, std::string password, unsigned int mode) {
	switch (mode) {
		case DER_KEYFILE:
			m_a2mxcrypto = new A2MXcrypto(keyfilepath);
			break;
		case ENCRYPTED_KEYFILE:
			m_a2mxcrypto = new A2MXcrypto(keyfilepath, str2sb(password));
			break;
		case PASSWORD_ONLY:
			m_a2mxcrypto = new A2MXcrypto(str2sb(password));
			break;
		default:
			throw A2MXcrypto::Error("Invalid mode");
	}
	m_a2mxpeer = new A2MXpeer(m_a2mxcrypto->pubkey());
}

Crypto::Crypto(std::string pubkey) {
	m_a2mxpeer = new A2MXpeer(str2sb(pubkey));
}

Crypto::~Crypto() {
	if (m_a2mxcrypto != 0)
		delete m_a2mxcrypto;
	if (m_a2mxpeer != 0)
		delete m_a2mxpeer;
}

std::string Crypto::pubkeyHash() {
	return sb2str(m_a2mxpeer->pubkeyHash());
}

std::string Crypto::pubkeyHashBase58() {
	return m_a2mxpeer->pubkeyHashBase58();
}

std::string Crypto::pubkeyCompressed() {
	return sb2str(m_a2mxpeer->pubkeyCompressed());
}

std::string Crypto::sign(std::string message) {
	if (m_a2mxcrypto == 0)
		throw A2MXcrypto::Error("Cannot sign without private key");
	return sb2str(m_a2mxcrypto->sign(str2sb(message)));
}

bool Crypto::verify(std::string message, std::string signature) {
	return m_a2mxpeer->verify(str2sb(message), str2sb(signature));
}

std::string Crypto::encrypt(std::string data) {
	return sb2str(m_a2mxpeer->encrypt(str2sb(data)));
}

std::string Crypto::decrypt(std::string data) {
	if (m_a2mxcrypto == 0)
		throw A2MXcrypto::Error("Cannot decrypt without private key");
	return sb2str(m_a2mxcrypto->decrypt(str2sb(data)));
}
