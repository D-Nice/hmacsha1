# solsha1
Pure-solidity implementation of the SHA1 hash function, heavily optimised using inline-assembly.

Gas consumption is approximately 56k per 512 bit block.

Due to the need for optimisation, Solidity does not detect the correct ABI for the contract. Once deployed, use the ABI defined by `iSHA1` to interact with the contract.

# hmacsha1
Extended to be able to use hmac-sha1, optimised with inline-assembly. Can be 'retrofit' to work with sha256 or other hash algorithms with a few simple changes.

If you end up using this, use hmacsha1.sol... since testRPC has some bugs, the testrpchmacsha1.sol contract is used during deployment, which only has a slight difference with L26 being enabled, which updates the free memory offset tracker to a 'safe' value for these tests (not safe outside of that), as testRPC's tracker seems to be starting at the calldata slot for whatever reason, on the last vector test. Hopefully if testRPC fixes this, no duplicate contract is needed and things can be cleaned up.

Depending on key length, hmac will run through the sha1 algo 2-3x, so ~99% of the gas costs will be originating mainly from sha1 at this point. With other precompile algos, it'll be reversed, and there's some room for making it further efficient there.