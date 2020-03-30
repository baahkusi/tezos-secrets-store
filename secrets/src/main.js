import '@babel/polyfill';
import 'mutationobserver-shim';
import Vue from 'vue';
import Vuex from 'vuex';
import './plugins/bootstrap-vue';
import App from './App.vue';
import sstore from './store';
import { Random } from 'random-js';
import { StoreType, TezosNodeWriter, TezosParameterFormat, TezosConseilClient, OperationKindType, ConseilQueryBuilder, ConseilOperator, ConseilDataClient } from 'conseiljs';
import { SecretStore, SecretStoreStorage, SecretStoreMichelson, SecretStoreStorageMichelson, credentials } from './contract';
var CryptoJS = require("crypto-js");
const argon2 = require('argon2-browser');
const blake = require('blakejs');
const arrayBufferToHex = require('array-buffer-to-hex');
const network = 'carthagenet';
const tezosNode = `https://tezos-dev.cryptonomic-infra.tech/`;
const conseilServer = {
  url: 'https://conseil-dev.cryptonomic-infra.tech:443',
  apiKey: 'galleon',
  network: network
};

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
  const iv = CryptoJS.enc.Base64.parse(nonce);
  private_key = CryptoJS.enc.Utf8.parse(private_key);
  const proof = CryptoJS.AES.encrypt(nonce, private_key, { iv: iv }).toString();

  if (hash) {
    return '0x' + blake.blake2bHex(proof, null, 32);
  }

  return '0x' + strToHex(proof);

}

Vue.prototype.$deployContract = async function (initialNonce, initialHashedProof, michelson = false) {

  const keystore = {
    publicKey: credentials[network].publicKey,
    privateKey: credentials[network].privateKey,
    publicKeyHash: credentials[network].publicKeyHash,
    seed: '',
    storeType: StoreType.Fundraiser
  };

  const fee = Number((await TezosConseilClient.getFeeStatistics(conseilServer, network, OperationKindType.Origination))[0]['high']);

  var nodeResult;

  if (michelson) {
    const contract = SecretStoreMichelson;

    const storage = SecretStoreStorageMichelson(initialNonce, initialHashedProof);

    nodeResult = await TezosNodeWriter.sendContractOriginationOperation(tezosNode, keystore, 0, undefined,
      fee, '', 1000, 100000, contract,
      storage, TezosParameterFormat.Michelson);
  } else {
    const contract = JSON.stringify(SecretStore);

    const storage = JSON.stringify(SecretStoreStorage(initialNonce, initialHashedProof));

    nodeResult = await TezosNodeWriter.sendContractOriginationOperation(tezosNode, keystore, 0, undefined,
      fee, '', 1000, 100000, contract,
      storage, TezosParameterFormat.Micheline);
  }

  const reg1 = /"/g;
  const reg2 = /\n/;
  const groupid = nodeResult['operationGroupID'].replace(reg1, '').replace(reg2, ''); // clean up RPC output
  const conseilResult = await TezosConseilClient.awaitOperationConfirmation(conseilServer, network, groupid, 5);
  return conseilResult;
}

Vue.prototype.$invokeContract = async function (KTAddress, params) {
  const keystore = {
    publicKey: credentials[network].publicKey,
    privateKey: credentials[network].privateKey,
    publicKeyHash: credentials[network].publicKeyHash,
    seed: '',
    storeType: StoreType.Fundraiser
  };

  console.log(params);

  // const args = `(Pair (Pair "${params.encryptedData}" ${params.hashedProof}) ${params.proof})`;

  const args = { "prim": "Pair", "args": [{ "prim": "Pair", "args": [{ "string": params.encryptedData }, { "bytes": params.hashedProof.replace('0x', '') }] }, { "bytes": params.proof.replace('0x', '')}] };

  console.log(args);

  const nodeResult = await TezosNodeWriter.sendContractInvocationOperation(tezosNode, keystore, KTAddress,
    10000, 100000, '', 1000, 100000,
    undefined, JSON.stringify(args), TezosParameterFormat.Micheline);

  const reg1 = /"/g;
  const reg2 = /\n/;
  const groupid = nodeResult['operationGroupID'].replace(reg1, '').replace(reg2, ''); // clean up RPC output
  const conseilResult = await TezosConseilClient.awaitOperationConfirmation(conseilServer, network, groupid, 5);
  return conseilResult;
}


Vue.prototype.$getCurrentNonce = async function (KTAddress) {
  const entity = 'accounts';
  const platform = 'tezos';
  let accountQuery = ConseilQueryBuilder.blankQuery();
  accountQuery = ConseilQueryBuilder.addFields(accountQuery, 'storage');
  accountQuery = ConseilQueryBuilder.addPredicate(accountQuery, 'account_id', ConseilOperator.EQ, [KTAddress], false);
  accountQuery = ConseilQueryBuilder.setLimit(accountQuery, 1);

  var result = await ConseilDataClient.executeEntityQuery(conseilServer, platform, network, entity, accountQuery);

  result = result[0].storage.split(' ');

  const nonce = Number(result[result.length - 1]);

  return nonce;
}

Vue.prototype.$randInt = function () {
  const random = new Random(); // uses the nativeMath engine
  return random.integer(1, 2 ** 32);
}

new Vue({
  store,
  render: h => h(App),
}).$mount('#app')
