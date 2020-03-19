import '@babel/polyfill';
import 'mutationobserver-shim';
import Vue from 'vue';
import Vuex from 'vuex';
import './plugins/bootstrap-vue';
import App from './App.vue';
import sstore from './store';
import AES from 'crypto-js/aes';
import utf8 from 'crypto-js/enc-utf8';
import { Random } from 'random-js';
import { StoreType, TezosNodeWriter, TezosParameterFormat, setLogLevel } from 'conseiljs';
const argon2 = require('argon2-browser');
const blake = require('blakejs');
const arrayBufferToHex = require('array-buffer-to-hex');
const tezosNode = '';

setLogLevel('debug');

Vue.config.productionTip = false
Vue.use(Vuex)
const store = new Vuex.Store(sstore);

Vue.prototype.$toKey = function (password, username) {
  return argon2.hash({
    pass: password,
    salt: username,
    // optional
    time: 100, // the number of iterations
    mem: 1024, // used memory, in KiB
    hashLen: 32, // desired hash length
    parallelism: 1, // desired parallelism (will be computed in parallel only for PNaCl)
    type: argon2.ArgonType.Argon2id, // or argon2.ArgonType.Argon2i
  });
};

function encryptData(dataStr, hexKey){
  var cipher = AES.encrypt(dataStr, hexKey).toString();

  var cipherBytes = new Uint8Array(Buffer.from(cipher));

  return arrayBufferToHex(cipherBytes);

}

Vue.prototype.$encryptData = encryptData;

Vue.prototype.$decryptData = function (dataCipher, hexKey) {
  const dataStr = AES.decrypt(dataCipher, hexKey).toString(utf8);
  return JSON.parse(dataStr);
};

Vue.prototype.$getKTAddress = function () {
  return localStorage.getItem('KTAddress');
};

Vue.prototype.$setKTAddress = function (KTAddress) {
  return localStorage.setItem('KTAddress', KTAddress);
};

Vue.prototype.$generateProof = function (private_key, nonce, hash = false) {
  const proof = encryptData(nonce, private_key);

  if (hash) {
    return '0x' + blake.blake2bHex(proof);
  }

  return proof;

}

Vue.prototype.$deployContract = async function (initialNonce, initialHashedProof) {
  const keystore = {
    publicKey: 'edpkvQtuhdZQmjdjVfaY9Kf4hHfrRJYugaJErkCGvV3ER1S7XWsrrj',
    privateKey: 'edskRgu8wHxjwayvnmpLDDijzD3VZDoAH7ZLqJWuG4zg7LbxmSWZWhtkSyM5Uby41rGfsBGk4iPKWHSDniFyCRv3j7YFCknyHH',
    publicKeyHash: 'tz1QSHaKpTFhgHLbqinyYRjxD5sLcbfbzhxy',
    seed: '',
    storeType: StoreType.Fundraiser
  };

  const contract = `[
    {
      "prim": "storage", "args": [
        {
          "prim": "pair", "args": [
            {
              "prim": "pair", "args": [
                {
                  "prim": "map", "args": [
                    { "prim": "bytes" }, { "prim": "string" }]
                  , "annots": ["%SecretStore"]
                }, { "prim": "bytes", "annots": ["%hashedProof"] }]
            }, { "prim": "int", "annots": ["%nonce"] }]
        }]
    },
    {
      "prim": "parameter", "args": [
        {
          "prim": "pair", "args": [
            {
              "prim": "pair", "args": [
                { "prim": "string", "annots": ["%encryptedData"] }, { "prim": "bytes", "annots": ["%nexthashedProof"] }]
            }, { "prim": "bytes", "annots": ["%proof"] }]
        }]
    },
    {
      "prim": "code", "args": [
        [{ "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CDR" }, { "prim": "BLAKE2B" }, { "prim": "COMPARE" }, { "prim": "EQ" },
        {
          "prim": "IF", "args": [
            [[]], [[{ "prim": "PUSH", "args": [{ "prim": "string" }, { "string": "WrongCondition: sp.blake2b(params.proof) == self.data.hashedProof" }] }, { "prim": "FAILWITH" }]]]
        }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "PACK" }, { "prim": "BLAKE2B" }, { "prim": "MEM" },
        {
          "prim": "IF", "args": [
            [[{ "prim": "PUSH", "args": [{ "prim": "string" }, { "string": "WrongCondition: ~ (self.data.SecretStore.contains(sp.blake2b(sp.pack(params.encryptedData))))" }] }, { "prim": "FAILWITH" }]], [[]]]
        }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "DIG", "args": [{ "int": "3" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "4" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "SOME" }, { "prim": "DIG", "args": [{ "int": "4" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "5" }] }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "PACK" }, { "prim": "BLAKE2B" }, { "prim": "UPDATE" }, { "prim": "PAIR" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "SWAP" }, { "prim": "DROP" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "CAR" }, { "prim": "PUSH", "args": [{ "prim": "int" }, { "int": "1" }] }, { "prim": "DIG", "args": [{ "int": "3" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "4" }] }, { "prim": "CDR" }, { "prim": "ADD" }, { "prim": "SWAP" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "SWAP" }, { "prim": "DROP" }, { "prim": "SWAP" }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "CAR" }, { "prim": "CAR" }, { "prim": "DIG", "args": [{ "int": "2" }] }, { "prim": "DUP" }, { "prim": "DUG", "args": [{ "int": "3" }] }, { "prim": "CAR" }, { "prim": "CDR" }, { "prim": "SWAP" }, { "prim": "PAIR" }, { "prim": "PAIR" }, { "prim": "DUG", "args": [{ "int": "2" }] }, { "prim": "DROP" }, { "prim": "DROP" },
        {
          "prim": "NIL", "args": [
            { "prim": "operation" }]
        }, { "prim": "PAIR" }]]
    }]`;

  const storage = `{
    "prim": "Pair", "args": [
      {
        "prim": "Pair", "args": [
          [], { "bytes": ${initialHashedProof} }]
      }, { "int": ${initialNonce} }]
  }`;

  const result = await TezosNodeWriter.sendContractOriginationOperation(tezosNode, keystore, 0, undefined, 100000, '', 1000, 100000, contract, storage, TezosParameterFormat.Micheline);
  console.log(`Injected operation group id ${result.operationGroupID}`);
}

Vue.prototype.$invokeContract = function () {

}

Vue.prototype.$randInt = function () {
  const random = new Random(); // uses the nativeMath engine
  return random.integer(1, 2 ** 32);
}

new Vue({
  store,
  render: h => h(App),
}).$mount('#app')
