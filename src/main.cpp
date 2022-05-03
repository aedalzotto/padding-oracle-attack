#include <future>
#include <iostream>
#include <iomanip>

#include <boost/program_options.hpp>

#include "PaddingOracle.hpp"

namespace po = boost::program_options;

void print_progress(unsigned decrypted, unsigned total);

int main(int argc, char *argv[])
{
	std::string url;
	try {
		po::options_description desc{"Padding Oracle Attack (for ASCII data)"};
		desc.add_options()
			("url", po::value<std::string>(&url)->required(), "URL to attack")
			("help", "produce help message")
		;

		po::positional_options_description p;
		p.add("url", -1);

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).
        	options(desc).positional(p).run(), vm);


		if (vm.count("help"))
		{
			std::cout << desc << "\n";
			return EXIT_SUCCESS;
		}

		po::notify(vm);
	} catch(std::exception& e){
		std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
	}

	std::cout << "Attacking URL: " << url << std::endl;

	PaddingOracle po(url);
	std::string cyphertext = po.get_cyphertext();

	std::cout << "Cyphertext:  " << cyphertext << std::endl;
	unsigned barlen = cyphertext.length() - 2 * CryptoPP::AES::BLOCKSIZE;

	print_progress(0, barlen);

	std::future<void> progress = std::async(
		[&] {
			unsigned bytes = 0;
			while(++bytes < barlen){
				po.wait_progress();
				print_progress(bytes, barlen);
			}
		}
	);

	std::future<std::string> worker = std::async(
		[&]() -> std::string {
			return po.attack(cyphertext);
		}
	);

	std::string plaintext = worker.get();
	progress.wait();

	std::cout << "Plaintext: " << plaintext << std::endl;

	return EXIT_SUCCESS;
}

void print_progress(unsigned decrypted, unsigned total)
{
	std::cout << 
		"\rDecrypted:                          " << 
		std::setw(3) << 
		std::setfill(' ') <<
		decrypted << "/" <<
		std::setw(3) << 
		std::setfill(' ') <<
		total / 2 << 
		" [" <<
		std::setw(total - decrypted*2) << 
		std::setfill(' ') << 
		"<<" << 
		std::setw(decrypted*2 + 1) <<
		std::setfill('=') <<
		"]" << std::flush;
}
