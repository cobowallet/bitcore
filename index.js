'use strict';

var dcrcore = module.exports;

// module information
dcrcore.version = 'v' + require('./package.json').version;
dcrcore.versionGuard = function(version) {
  if (version !== undefined) {
    var message = 'More than one instance of bitcore-lib found. ' +
      'Please make sure to require bitcore-lib and check that submodules do' +
      ' not also include their own bitcore-lib dependency.';
    throw new Error(message);
  }
};
dcrcore.versionGuard(global._dcrcore);
global._dcrcore = dcrcore.version;

// crypto
dcrcore.crypto = {};
dcrcore.crypto.BN = require('./lib/crypto/bn');
dcrcore.crypto.ECDSA = require('./lib/crypto/ecdsa');
dcrcore.crypto.Hash = require('./lib/crypto/hash');
dcrcore.crypto.Random = require('./lib/crypto/random');
dcrcore.crypto.Point = require('./lib/crypto/point');
dcrcore.crypto.Signature = require('./lib/crypto/signature');

// encoding
dcrcore.encoding = {};
dcrcore.encoding.Base58 = require('./lib/encoding/base58');
dcrcore.encoding.Base58Check = require('./lib/encoding/base58check');
dcrcore.encoding.BufferReader = require('./lib/encoding/bufferreader');
dcrcore.encoding.BufferWriter = require('./lib/encoding/bufferwriter');
dcrcore.encoding.Varint = require('./lib/encoding/varint');

// utilities
dcrcore.util = {};
dcrcore.util.buffer = require('./lib/util/buffer');
dcrcore.util.js = require('./lib/util/js');
dcrcore.util.preconditions = require('./lib/util/preconditions');

// errors thrown by the library
dcrcore.errors = require('./lib/errors');

// main bitcoin library
dcrcore.Address = require('./lib/address');
dcrcore.Block = require('./lib/block');
dcrcore.MerkleBlock = require('./lib/block/merkleblock');
dcrcore.BlockHeader = require('./lib/block/blockheader');
dcrcore.HDPrivateKey = require('./lib/hdprivatekey.js');
dcrcore.HDPublicKey = require('./lib/hdpublickey.js');
dcrcore.Networks = require('./lib/networks');
dcrcore.Opcode = require('./lib/opcode');
dcrcore.PrivateKey = require('./lib/privatekey');
dcrcore.PublicKey = require('./lib/publickey');
dcrcore.Script = require('./lib/script');
dcrcore.Transaction = require('./lib/transaction');
dcrcore.URI = require('./lib/uri');
dcrcore.Unit = require('./lib/unit');

// dependencies, subject to change
dcrcore.deps = {};
dcrcore.deps.bnjs = require('bn.js');
dcrcore.deps.bs58 = require('bs58');
dcrcore.deps.Buffer = Buffer;
dcrcore.deps.elliptic = require('elliptic');
dcrcore.deps._ = require('lodash');

// Internal usage, exposed for testing/advanced tweaking
dcrcore._HDKeyCache = require('./lib/hdkeycache');
dcrcore.Transaction.sighash = require('./lib/transaction/sighash');
