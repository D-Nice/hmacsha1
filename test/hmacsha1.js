const iSHA1 = artifacts.require('./iSHA1.sol')
const SHA1 = artifacts.require('./SHA1.sol')
const HMACSHA1 = artifacts.require('./HMACSHA1.sol')
const vectors = require('hash-test-vectors/hmac.json')

contract('HMACSHA1', function(accounts) {
    let totalGas = 0;
    vectors.forEach(function(v, i) {
        it.only('hmacsha1.sol against test vector ' + i, async function() {
            const sha1Address = (await SHA1.deployed()).address
            const hmacInstance = (await HMACSHA1.deployed())
            const key = '0x' + v.key
            const msg = '0x' + v.data

            const gas = await hmacInstance.hmac.estimateGas(key, msg, sha1Address)
            console.log('\tCurrent gas: ' + gas)
            totalGas += gas
            console.log('\tCumulative gas: ' + totalGas)

            let res = await hmacInstance.hmac(key, msg, sha1Address)
            if (v.truncate)
                res = res.slice(0, v.truncate*2 + 2)

            /*const crypto = require('crypto')
            console.log(crypto.createHmac('sha1', new Buffer(v.key, 'hex')).update(Buffer.from(v.data, 'hex')).digest('hex'))*/
            assert.equal(res, '0x' + v.sha1, `wrong hmacsha1 for key ${key} with msg ${msg}`)
        })
    })
})
