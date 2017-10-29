pragma solidity ^0.4.15;

import "./sha1.sol";

contract HMACSHA1 {
  /* can be made even more efficient, by removing some dynamic checks and making it even more exclusive(which it already is) to SHA1 (which were left in to be reused for other hmacs)... currently mixed some parts are dynamic, others static and specific to sha1 only
  */

  function hmac(bytes key, bytes message, address hashCode) constant returns (bytes20) {
    iSHA1 shaLib = iSHA1(hashCode);
    bytes20 digest;
    if (key.length > 64) {
      digest = shaLib.sha1(key);
      assembly {
        // incrementing freemem here after an external call
        // may be safer, but more expensive
        //mstore(0x40, msize)
        mstore(add(key, 32), digest)
        mstore(key, 20)
      }
    }

    if (key.length < 64) {
      assembly {
        mstore(add(mload(0x40), 32), mload(add(key, 32)))
        key := mload(0x40)
        mstore(add(key, 64), 0)
        mstore(key, 64)
        mstore(0x40, msize)
      }
    }

    bytes memory o_key_pad;
    bytes memory i_key_pad;
    bytes memory pass1;
    assembly {
      o_key_pad := mload(0x40)
      mstore(o_key_pad, 64)
      mstore(add(o_key_pad, 32), xor(mload(add(key, 32)), 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c))
      mstore(add(o_key_pad, 64), xor(mload(add(key, 64)), 0x5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c))
      mstore(0x40, msize)

      i_key_pad := mload(0x40)
      mstore(i_key_pad, 64)
      mstore(add(i_key_pad, 32), xor(mload(add(key, 32)), 0x3636363636363636363636363636363636363636363636363636363636363636))
      mstore(add(i_key_pad, 64), xor(mload(add(key, 64)), 0x3636363636363636363636363636363636363636363636363636363636363636))
      mstore(0x40, msize)

      pass1 := mload(0x40)
      mstore(pass1, add(mload(i_key_pad), mload(message)))
      mstore(0x40, msize)
    }
    copyBytes(i_key_pad, 0, i_key_pad.length, pass1, 0);
    copyBytes(message, 0, message.length, pass1, i_key_pad.length);

    // workaround for other resize which seems to fail
    assembly {
      mstore(0x40, msize)
    }

    digest = shaLib.sha1(pass1);
    bytes memory pass2;

    assembly {
      // mstore(0x40, msize) this causes all hmacs to fail
      pass2 := mload(0x40)
      mstore(pass2, add(mload(o_key_pad), 20)) // set length to current o_pad + hash length of 20 bytes from sha1
      mstore(0x40, msize)
    }

    copyBytes(o_key_pad, 0, o_key_pad.length, pass2, 0);
    assembly {
      mstore(add(add(pass2, 32), mload(o_key_pad)), digest)
    }

    return shaLib.sha1(pass2);
  }

  // potential room for improvement here, this accounts for at least half the
  // gas costs in the hmac (not counting sha1)
  function copyBytes(bytes from, uint fromOffset, uint length, bytes to, uint toOffset)
  private returns (bytes) {

    uint minLength = length + toOffset;

    if (to.length < minLength) {
      // Buffer too small
      // TODO audit/recheck below!!!
      assembly {
        add(minLength, toOffset)
        to
        mstore
      }
      bytes memory newSized = new bytes(minLength);
      newSized = to;
      to = newSized;
    }

    // NOTE: the offset 32 is added to skip the `size` field of both bytes variables
    uint i = 32 + fromOffset;
    uint j = 32 + toOffset;

    while (i < (32 + fromOffset + length)) {
      assembly {
        let tmp := mload(add(from, i))
        mstore(add(to, j), tmp)
      }
      i += 32;
      j += 32;
    }

    return to;
  }
}