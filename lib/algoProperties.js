const crypto = require('crypto');  // Fix for incorrect implementation of scrypt
var multiHashing = require('multi-hashing');
var util = require('./util.js');

var diff1 = global.diff1 = 0x00000000ffff0000000000000000000000000000000000000000000000000000;

var algos = module.exports = global.algos = {
    'sha256': {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '00000000ffff0000000000000000000000000000000000000000000000000000',

        hash: function(coinConfig) {
            rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = crypto.createHash('sha256').update(data).digest();
                        const hash2 = crypto.createHash('sha256').update(hash1).digest();
                        resolve(hash2);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'scrypt': {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        // Sando: migration from multi-hashing to crypto as original multi-hashing is broken
        hash: function(coinConfig) {
            const N = coinConfig.nValue || 1024;
            const r = coinConfig.rValue || 1;
            const p = 1;
            const dklen = 32;  // 256 bits = 32 bytes
            return function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        crypto.scrypt(data, data, dklen, { N, r, p }, (err, derivedKey) => {
                            if (err) { reject(err); }
                            else { resolve(derivedKey); }
                        });
                    } catch (err) { reject(err); }
                });
            };
        }
    },
    'scrypt-og': {
        //Uncomment diff if you want to use hardcoded truncated diff
        //diff: '0000ffff00000000000000000000000000000000000000000000000000000000',
        multiplier: Math.pow(2, 16),
        // Sando: migration from multi-hashing to crypto as original multi-hashing is broken
        hash: function(coinConfig) {
            const N = coinConfig.nValue || 64;
            const r = coinConfig.rValue || 1;
            const p = 1;
            const dklen = 32;  // 256 bits = 32 bytes
            return function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        crypto.scrypt(data, data, dklen, { N, r, p }, (err, derivedKey) => {
                            if (err) { reject(err); }
                            else { resolve(derivedKey); }
                        });
                    } catch (err) { reject(err); }
                });
            };
        }
    },
    'x11': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.x11.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'x13': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.x13.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'x15': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.x15.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'nist5': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.nist5.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'quark': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.quark.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'keccak': {
        hash: function (coinConfig) {
            if (coinConfig.normalHashing) {
                return function (data, nTimeInt) {
                    return new Promise((resolve, reject) => {
                        try {
                            const hexString = nTimeInt.toString(16);
                            if (hexString.length % 2 !== 0) {
                                hexString = '0' + hexString;
                            }
                            const hash1 = multiHashing.keccak(multiHashing.keccak(Buffer.concat([data, Buffer.from(hexString, 'hex')])));
                            resolve(hash1);
                        } catch (err) { reject(err); }
                    });
                }
            } else {
                return function () {
                    return new Promise((resolve, reject) => {
                        try {
                            const hash1 = multiHashing.keccak.apply(this, arguments);
                            resolve(hash1);
                        } catch (err) { reject(err); }
                    });
                }
            }
        }
    },
    'skein': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.skein.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'groestl': {
        multiplier: Math.pow(2, 8),
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.groestl.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'fugue': {
        multiplier: Math.pow(2, 8),
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.fugue.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'shavite3': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.shavite3.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'hefty1': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.hefty1.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
    'qubit': {
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.qubit.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    },
/*    'lyra2re': {
        multiplier: Math.pow(2, 7),
        hash: function(coinConfig) {
            var rts = function(data) {
                return new Promise((resolve, reject) => {
                    try {
                        const hash1 = multiHashing.lyra2re.apply(this, arguments);
                        resolve(hash1);
                    } catch (err) { reject(err); }
                });
            }
            return rts;
        }
    }, */ //Need to verify!

};

for (var algo in algos){
    if (!algos[algo].multiplier)
        algos[algo].multiplier = 1;
}
