const crypto = require('crypto');
const deasync = require('deasync');
// remove next line when migration done
var multiHashing = require('multi-hashing');
var util = require('./util.js');

var diff1 = global.diff1 = 0x00000000ffff0000000000000000000000000000000000000000000000000000;

var algos = module.exports = global.algos = {
    sha256: {   // worked fine, but switched to crypto lib
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '00000000ffff0000000000000000000000000000000000000000000000000000',

        hash: function() {
            return function(data) {
                const hash = crypto.createHash('sha256').update(data).digest();
                const doubleHash = crypto.createHash('sha256').update(hash).digest();
                return doubleHash;
            };
        }
    },
    'scrypt': {   // broken native lib -> switch to crypto lib
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        // Sando: migration from multi-hashing to crypto
        hash: function(coinConfig) {
            const N = coinConfig.nValue || 1024;
            const r = coinConfig.rValue || 1;
            const p = 1;
            const dklen = 32;  // 256 bits = 32 bytes
            return function(data) {
                const message = data;
                const salt = data;
                var derivedKey;
                var done = false;
                crypto.scrypt(message, salt, dklen, { N, r, p: 1 }, (err, key) => {
                    if (err) {
                        throw err;
                    } else {
                        derivedKey = key;
                        done = true;
                    }
                });
                // wait until async function finished
                while (!done) {
                    deasync.sleep(5);
                }
                return derivedKey;
            };
        }
    },
    'scrypt-og': {      // broken native lib -> switch to crypto lib
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        // Sando: migration from multi-hashing to crypto
        hash: function(coinConfig) {
            const N = coinConfig.nValue || 65;
            const r = coinConfig.rValue || 1;
            const p = 1;
            const dklen = 32;  // 256 bits = 32 bytes
            return function(data) {
                const message = data;
                const salt = data;
                var derivedKey;
                var done = false;
                crypto.scrypt(message, salt, dklen, { N, r, p: 1 }, (err, key) => {
                    if (err) {
                        throw err;
                    } else {
                        derivedKey = key;
                        done = true;
                    }
                });
                // wait until async function finished
                while (!done) {
                    deasync.sleep(5);
                }
                return derivedKey;
            };
        }
    },
/*    'scrypt-jane': {     // broken native lib -> disabled
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){
            var nTimestamp = coinConfig.chainStartTime || 1367991200;
            var nMin = coinConfig.nMin || 4;
            var nMax = coinConfig.nMax || 30;
            return function(data, nTime){
                return multiHashing.scryptjane(data, nTime, nTimestamp, nMin, nMax);
            }
        }
    }, */
/*    'scrypt-n': {   // broken native lib -> disabled
        multiplier: Math.pow(2, 16),
        hash: function(coinConfig){

            var timeTable = coinConfig.timeTable || {
                "2048": 1389306217, "4096": 1456415081, "8192": 1506746729, "16384": 1557078377, "32768": 1657741673,
                "65536": 1859068265, "131072": 2060394857, "262144": 1722307603, "524288": 1769642992
            };

            var nFactor = (function(){
                var n = Object.keys(timeTable).sort().reverse().filter(function(nKey){
                    return Date.now() / 1000 > timeTable[nKey];
                })[0];

                var nInt = parseInt(n);
                return Math.log(nInt) / Math.log(2);
            })();

            return function(data) {
                return multiHashing.scryptn(data, nFactor);
            }
        }
    },*/
/*    sha1: {  // broken native lib -> disabled
        hash: function(){
            return function(){
                return multiHashing.sha1.apply(this, arguments);
            }
        }
    },*/
    x11: {
        hash: function(){
            return function(){
                return multiHashing.x11.apply(this, arguments);
            }
        }
    },
    x13: {
        hash: function(){
            return function(){
                return multiHashing.x13.apply(this, arguments);
            }
        }
    },
    x15: {
        hash: function(){
            return function(){
                return multiHashing.x15.apply(this, arguments);
            }
        }
    },
    nist5: {
        hash: function(){
            return function(){
                return multiHashing.nist5.apply(this, arguments);
            }
        }
    },
    quark: {
        hash: function(){
            return function(){
                return multiHashing.quark.apply(this, arguments);
            }
        }
    },
    keccak: {
        multiplier: Math.pow(2, 8),
        hash: function(coinConfig){
            if (coinConfig.normalHashing === true) {
                return function (data, nTimeInt) {
                    var hexString = nTimeInt.toString(16);
                    if (hexString.length % 2 !== 0) {
                        hexString = '0' + hexString;
                    }
                    return multiHashing.keccak(multiHashing.keccak(Buffer.concat([data, Buffer.from(hexString, 'hex')])));
                };
            }
            else {
                return function () {
                    return multiHashing.keccak.apply(this, arguments);
                }
            }
        }
    },
/*    blake: {   // broken native lib -> disabled
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.blake.apply(this, arguments);
            }
        }
    },*/
    skein: {
        hash: function(){
            return function(){
                return multiHashing.skein.apply(this, arguments);
            }
        }
    },
    groestl: {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.groestl.apply(this, arguments);
            }
        }
    },
    fugue: {
        multiplier: Math.pow(2, 8),
        hash: function(){
            return function(){
                return multiHashing.fugue.apply(this, arguments);
            }
        }
    },
    shavite3: {
        hash: function(){
            return function(){
                return multiHashing.shavite3.apply(this, arguments);
            }
        }
    },
    hefty1: {
        hash: function(){
            return function(){
                return multiHashing.hefty1.apply(this, arguments);
            }
        }
    },
    qubit: {
        hash: function(){
            return function(){
                return multiHashing.qubit.apply(this, arguments);
            }
        }
    },
/*    'yescrypt': {  // broken native lib -> disabled
        multiplier: Math.pow(2, 16),
        hash: function(){
            return function(){
                return multiHashing.yescrypt.apply(this, arguments);
            }
        }
    }, */
/*    s3: {    // broken native lib -> disabled
        hash: function(){
            return function(){
                return multiHashing.s3.apply(this, arguments);
            }
        }
    }, */
/*    lyra2re: {  // untested -> disabled
        multiplier: Math.pow(2, 7),
        hash: function(){
            return function(){
                return multiHashing.lyra2re.apply(this, arguments);
            }
        }
    }, */
/*    neoscrypt: {  // broken native lib -> disabled
        multiplier: Math.pow(2, 16),
        hash: function(){
            return function(){
                return multiHashing.neoscrypt.apply(this, arguments);
            }
        }
    },*/
/*    dcrypt: {  // broken native lib -> disabled
        hash: function(){
            return function(){
                return multiHashing.dcrypt.apply(this, arguments);
            }
        }
     }*/
};


for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;
}
