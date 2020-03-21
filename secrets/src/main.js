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
import { StoreType, TezosNodeWriter, TezosParameterFormat } from 'conseiljs';
import { SecretStore, SecretStoreStorage } from './contract'
const argon2 = require('argon2-browser');
const blake = require('blakejs');
const arrayBufferToHex = require('array-buffer-to-hex');
const tezosNode = '';

// setLogLevel('debug');

Vue.config.productionTip = false
Vue.use(Vuex)
const store = new Vuex.Store(sstore);

Vue.prototype.$toKey = function (password, username) {
  return argon2.hash({
    pass: password,
    salt: username,
    // optional
    time: Vue.config.devtools ? 10000 : 100, // the number of iterations
    mem: Vue.config.devtools ? 2048 : 1024, // used memory, in KiB
    hashLen: 64, // desired hash length
    parallelism: 1, // desired parallelism (will be computed in parallel only for PNaCl)
    type: argon2.ArgonType.Argon2id, // or argon2.ArgonType.Argon2i
  });
};

function encryptData(dataStr, hexKey) {
  var cipher = AES.encrypt(dataStr, hexKey).toString();

  var cipherBytes = Buffer.from(cipher);

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
    return '0x' + blake.blake2bHex(proof, null, 32);
  }

  return proof;

}

Vue.prototype.$deployContract = async function (initialNonce, initialHashedProof) {
  const keystore = {
    publicKey: 'edpkuH4EMzK1jZSU8836SqZKc9RxY2aCKwK2KzPhqobb6zVk5TkTvV',
    privateKey: 'edskRpMHNHjKqbJ1jZZd6oLpLC3jFujmY2nqoc7cxkBDnvhzfbc9zVc4ZZS1czBtXRPsu2A2LeU6DNwvzadQ5xDUVqun1ic4t6',
    publicKeyHash: 'tz1QCRznmbFuix8PkXwgRZ626giv4ENRshWK',
    seed: '',
    storeType: StoreType.Fundraiser
  };

  const contract = SecretStore;

  const storage = SecretStoreStorage(initialNonce, initialHashedProof);

  const result = await TezosNodeWriter.sendContractOriginationOperation(tezosNode, keystore, 0, undefined, 100000, '', 1000, 100000, contract, storage, TezosParameterFormat.Micheline);
  console.log(`Injected operation group id ${result.operationGroupID}`);
}

Vue.prototype.$invokeContract = function () {
  return true;
}

Vue.prototype.$randInt = function () {
  const random = new Random(); // uses the nativeMath engine
  return random.integer(1, 2 ** 32);
}

new Vue({
  store,
  render: h => h(App),
}).$mount('#app')
