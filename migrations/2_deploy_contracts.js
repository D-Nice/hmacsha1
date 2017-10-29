const SHA1 = artifacts.require('./SHA1.sol')
const HMACSHA1 = artifacts.require('./HMACSHA1.sol')

module.exports = function(deployer) {
  deployer.deploy(SHA1)
  deployer.deploy(HMACSHA1)
}
