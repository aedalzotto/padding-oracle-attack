#include <iostream>
#include <iomanip>

#include "PaddingOracle.hpp"

int main(int argc, char *argv[])
{
	std::string url = "http://crypto-class.appspot.com/po?er=";

	PaddingOracle po(url);

	std::string cyphertext = po.get_cyphertext();

	std::cout << "Attacking cyphertext: " << cyphertext << std::endl;

	po.attack(cyphertext);

	return EXIT_SUCCESS;
}
