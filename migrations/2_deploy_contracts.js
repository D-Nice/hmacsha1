const SHA1 = artifacts.require('./SHA1.sol')
const HMACSHA1 = artifacts.require('./testrpcHMACSHA1.sol')

module.exports = function(deployer) {
  deployer.deploy(SHA1)
  deployer.deploy(HMACSHA1)
}
