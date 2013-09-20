#include <string>

#include "a2mxcrypto.h"

class Crypto {
	public:
		Crypto(std::string keyfilepath, std::string password);
		Crypto(std::string pubkey_data);
		~Crypto();

		std::string pubkeyHash();
		std::string pubkeyHashBase58();
		std::string pubkeyData();
		std::string pubkeyAddress();

		bool hasPrivkey() {
			return m_a2mxcrypto->hasPrivkey();
		}

		std::string signAddress(std::string message);
		bool verifyAddress(std::string message, std::string signature);

		std::string sign(std::string message);
		bool verify(std::string message, std::string signature);

		std::string encrypt(std::string data);
		std::string decrypt(std::string data);

		static void createNewKeyFile(const std::string& keyfilepath, std::string password);

	private:
		A2MXcrypto* m_a2mxcrypto = 0;
};
