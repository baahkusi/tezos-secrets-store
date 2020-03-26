import '@babel/polyfill';
import 'mutationobserver-shim';
import Vue from 'vue';
import Vuex from 'vuex';
import './plugins/bootstrap-vue';
import App from './App.vue';
import sstore from './store';
import { Random } from 'random-js';
import { StoreType, TezosNodeWriter, TezosParameterFormat } from 'conseiljs';
import { SecretStore, SecretStoreStorage } from './contract';
var CryptoJS = require("crypto-js");
const argon2 = require('argon2-browser');
const blake = require('blakejs');
const arrayBufferToHex = require('array-buffer-to-hex');
const tezosNode = 'https://carthagenet.SmartPy.io';
// const network = 'carthagenet';
// const conseilServer = {
//   url: 'https://conseil-dev.cryptonomic-infra.tech:443',
//   apiKey: 'b9labs', network
// };

Vue.config.productionTip = false
Vue.use(Vuex)
const store = new Vuex.Store(sstore);

Vue.prototype.$toKey = function (password, username) {
  return argon2.hash({
    pass: password,
    salt: username,
    // optional
    time: Vue.config.devtools ? 100 : 10000, // the number of iterations
    mem: 1024, // used memory, in KiB
    hashLen: 64, // desired hash length
    parallelism: 1, // desired parallelism (will be computed in parallel only for PNaCl)
    type: argon2.ArgonType.Argon2id, // or argon2.ArgonType.Argon2i
  });
};

function strToHex(str) {
  var bytes = Buffer.from(str);

  return arrayBufferToHex(bytes);
}


Vue.prototype.$encryptData = function (dataStr, pKey, hex = false) {
  var cipher = CryptoJS.AES.encrypt(dataStr, pKey).toString();

  if (!hex) {
    return cipher;
  }

  return strToHex(cipher);

};

Vue.prototype.$decryptData = function (dataCipher, pKey) {
  const dataStr = CryptoJS.AES.decrypt(dataCipher, pKey).toString(CryptoJS.enc.Utf8);
  return JSON.parse(dataStr);
};

Vue.prototype.$getKTAddress = function () {
  return localStorage.getItem('KTAddress');
};

Vue.prototype.$setKTAddress = function (KTAddress) {
  return localStorage.setItem('KTAddress', KTAddress);
};

Vue.prototype.$generateProof = function (private_key, nonce, hash = false) {

  // if we are hashing (hash == true) then we use utf string
  // if we are creating proof (hash == false) we return hex of proof

  // the order is important
  const iv = CryptoJS.enc.Base64.parse(private_key);
  private_key = CryptoJS.enc.Utf8.parse(private_key);
  const proof = CryptoJS.AES.encrypt(nonce, private_key, { iv: iv }).toString();

  console.log(proof);
  if (hash) {
    return '0x' + blake.blake2bHex(proof, null, 32);
  }

  return strToHex(proof);

}

Vue.prototype.$deployContract = async function (initialNonce, initialHashedProof) {

  const keystore = {
    publicKey: 'edpkuH4EMzK1jZSU8836SqZKc9RxY2aCKwK2KzPhqobb6zVk5TkTvV',
    privateKey: 'edskRpMHNHjKqbJ1jZZd6oLpLC3jFujmY2nqoc7cxkBDnvhzfbc9zVc4ZZS1czBtXRPsu2A2LeU6DNwvzadQ5xDUVqun1ic4t6',
    publicKeyHash: 'tz1QCRznmbFuix8PkXwgRZ626giv4ENRshWK',
    seed: '',
    storeType: StoreType.Fundraiser
  };

  const contract = JSON.stringify(SecretStore);

  const storage = JSON.stringify(SecretStoreStorage(initialNonce, initialHashedProof));

  const nodeResult = await TezosNodeWriter.sendContractOriginationOperation(tezosNode, keystore, 0, undefined, 100000, '', 1000, 100000, contract, storage, TezosParameterFormat.Micheline);

  return nodeResult;
  // const reg1 = '/"/g';
  // const reg2 = /\n/;
  // const groupid = nodeResult['operationGroupID'].replace(reg1, '').replace(reg2, ''); // clean up RPC output
  // console.log(`Injected operation group id ${groupid}`);
  // const conseilResult = await TezosConseilClient.awaitOperationConfirmation(conseilServer, network, groupid, 5);
  // console.log(`Originated contract at ${conseilResult[0].originated_contracts}`);
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
