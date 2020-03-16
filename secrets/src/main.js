import '@babel/polyfill';
import 'mutationobserver-shim';
import Vue from 'vue';
import Vuex from 'vuex';
import './plugins/bootstrap-vue';
import App from './App.vue';
import sstore from './store';
import AES from 'crypto-js/aes';
import utf8 from 'crypto-js/enc-utf8';
import { Random } from "random-js";
const argon2 = require('argon2-browser');
const blake = require('blakejs')

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

Vue.prototype.$encryptData = function (dataStr, hexKey) {
  return AES.encrypt(dataStr, hexKey).toString();
};

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
  const proof = AES.encrypt(nonce, private_key).toString();

  if (hash) {
    return blake.blake2bHex(proof);
  }

  return proof;

}

Vue.prototype.$randInt = function () {
  const random = new Random(); // uses the nativeMath engine
  return random.integer(1, 2**32);
}

new Vue({
  store,
  render: h => h(App),
}).$mount('#app')
