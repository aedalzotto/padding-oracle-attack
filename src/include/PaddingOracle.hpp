#pragma once

#include <string>

#include <cpr/cpr.h>

class PaddingOracle {
public:
	PaddingOracle(const std::string &url);

	std::string get_cyphertext();

	void attack(const std::string &cyphertext);

private:
	std::string url;

	bool query(const std::string &cyphertext);
	std::vector<std::string> cypher_to_blocks(const std::string &cyphertext);
	std::string decrypt_block(const std::string &c2, const std::string &c1);
	void set_guess(char *guess, unsigned value);
	std::string decode_block(const std::string &block);

};
