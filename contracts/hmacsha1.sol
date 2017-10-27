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
        mstore(add(key, 32), digest)
        mstore(key, 20)
      }
      // delete digest; useless, doesn't delete item from stack
      // also compiler now regulates balanced stack...
      // allow us to remove from stack pl0x
    }

    if (key.length < 64) {
      assembly {
        // NOTE enable for testrpc
        // mstore(0x40, 0x400) // FIXME testrpc workaround, seems the free memory
        // offset tracker is broken there with long calladata?
        mstore(add(mload(0x40), 32), mload(add(key, 32)))
        key := mload(0x40)
        mstore(key, 64)

        /* Dynamic memory resize for general hmac
        switch mload(key)
        case 0 {}
        default {
          mstore(0x40, add(mload(0x40), mul(div(sub(mload(key), 1), 32), 0x10)))
        }
        */
        mstore(0x40, add(mload(0x40), mul(3, 0x20)))
      }
    }

    bytes memory o_pad = hex'5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c';
    bytes memory i_pad = hex'36363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636';
    bytes memory o_key_pad;
    bytes memory i_key_pad;
    bytes memory pass1;
    assembly {
      o_key_pad := mload(0x40)
      mstore(o_key_pad, 64)
      mstore(0x40, add(mload(0x40), mul(3, 0x20)))
      mstore(add(o_key_pad, 32), xor(mload(add(o_pad, 32)), mload(add(key, 32))))
      mstore(add(o_key_pad, 64), xor(mload(add(o_pad, 64)), mload(add(key, 64))))
      i_key_pad := mload(0x40)
      mstore(i_key_pad, 64)
      mstore(0x40, add(mload(0x40), mul(3, 0x20)))
      mstore(add(i_key_pad, 32), xor(mload(add(i_pad, 32)), mload(add(key, 32))))
      mstore(add(i_key_pad, 64), xor(mload(add(i_pad, 64)), mload(add(key, 64))))
      pass1 := mload(0x40)
      mstore(pass1, add(mload(i_key_pad), mload(message)))
      mstore(0x40, add(mload(0x40), add(mul(div(mload(pass1), 32), 0x20), 0x20)))
      /*for { let i:= 0 } lt(i, div(mload(pass1), 32)) { i:= add(i,1) } {
          mstore(add(add(pass1, 32), mul(i, 32)), )
      }*/
    }
    copyBytes(i_key_pad, 0, i_key_pad.length, pass1, 0);
    copyBytes(message, 0, message.length, pass1, i_key_pad.length);

    digest = shaLib.sha1(pass1);

    bytes memory pass2;
    assembly {
      pass2 := mload(0x40)
      mstore(pass2, add(mload(o_key_pad), 20))
      mstore(0x40, add(mload(0x40), add(mul(div(mload(pass2), 32), 0x20), 0x20)))
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