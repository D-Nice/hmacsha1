# solsha1
Pure-solidity implementation of the SHA1 hash function, heavily optimised using inline-assembly.

Gas consumption is approximately 56k per 512 bit block.

Due to the need for optimisation, Solidity does not detect the correct ABI for the contract. Once deployed, use the ABI defined by `iSHA1` to interact with the contract.

# hmacsha1
Extended to be able to use hmac-sha1, optimised with inline-assembly. Can be 'retrofit' to work with sha256 or other hash algorithms with a few simple changes.

Depending on key length, hmac will run through the sha1 algo 2-3x, so ~99% of the gas costs will be originating mainly from sha1 at this point. With other precompile algos, it'll be reversed, and there's some room for making it further efficient there.