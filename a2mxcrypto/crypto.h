#include <string>

#include "a2mxcrypto.h"

class Crypto {
	public:
		static const unsigned int PASSWORD_ONLY = 0;
		static const unsigned int ENCRYPTED_KEYFILE = 1;
		static const unsigned int DER_KEYFILE = 2;

		Crypto(std::string a, std::string b, unsigned int mode = 1);
		Crypto(std::string pubkey);
		~Crypto();

		std::string pubkeyCompressed();
		std::string pubkeyHash();
		std::string pubkeyHashBase58();

		bool hasPrivkey() {
			return m_a2mxcrypto != 0;
		}

		std::string sign(std::string message);
		bool verify(std::string message, std::string signature);

		std::string encrypt(std::string data);
		std::string decrypt(std::string data);

	private:
		A2MXcrypto* m_a2mxcrypto = 0;
		A2MXpeer* m_a2mxpeer = 0;
};
