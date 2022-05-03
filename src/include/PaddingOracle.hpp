#pragma once

#include <string>
#include <semaphore>

#include <cpr/cpr.h>
#include <cryptopp/aes.h>

class PaddingOracle {
public:
	PaddingOracle(const std::string &url);

	std::string get_cyphertext();
	std::string attack(const std::string &cyphertext);
	void wait_progress();

private:
	std::string url;
	std::counting_semaphore<> smphr;

	bool query(const std::string &cyphertext);
	std::vector<std::string> cypher_to_blocks(const std::string &cyphertext);
	std::string decrypt_block(const std::string &c2, const std::string &c1);
	void set_guess(char *guess, unsigned value);
	std::string decode_block(const std::string &block);
};
