<template>
  <div>
    <b-form @submit="onSubmit">
      <b-form-group id="input-secret" label="Secret:" label-for="secret" description>
        <b-form-textarea
          id="secret"
          v-model="form.secret"
          type="text"
          required
          placeholder="Paste your secret here."
        ></b-form-textarea>
      </b-form-group>

      <b-form-group id="input-description" label="Description:" label-for="description">
        <b-form-textarea
          id="description"
          v-model="form.description"
          type="description"
          required
          placeholder="Add a little description to the secret, just to remind yourself later."
        ></b-form-textarea>
      </b-form-group>

      <b-button type="submit" variant="primary">Add Secret</b-button>
    </b-form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      form: {
        secret: "",
        description: ""
      }
    };
  },
  methods: {
    validateForm(){
      if(!this.form.secret.trim() || !this.form.description.trim()){
        this.$bvToast.toast(
          "Secret and description are both required",
          {
            title: "Form Validation  ...",
            variant: "danger",
            solid: true
          }
        );
        return false;
      }
      const hex = true;
      return this.$encryptData(JSON.stringify(this.form), this.$store.state.private_key, hex)
    },
    async invokeSetSecret(currentProof, nextProofHash, secret, KTAddress){
      
      const params = {
        encryptedData: secret,
        hashedProof: nextProofHash,
        proof: currentProof
      };

      const results = await this.$invokeContract(KTAddress, params);
      console.log(results);
    },
    async onSubmit(evt) {
      evt.preventDefault();
      
      if (!this.$store.state.authed) {
        this.$bvToast.toast(
          "You need to provide your auth credentials first.",
          {
            title: "Adding Secret  ...",
            variant: "danger",
            solid: true
          }
        );

        return;
      }

      const secret = this.validateForm();

      if (!secret){
        return;
      }

      if (this.$getKTAddress()) {

        const hash = true;
        // get current nonce
        var currentNonce = await this.$getCurrentNonce(this.$getKTAddress());
        // generate current proof
        const currentProof = this.$generateProof(this.$store.state.private_key, currentNonce.toString());
        // generate next proofHash
        const nextProofHash = this.$generateProof(this.$store.state.private_key, (++currentNonce).toString(), hash);
        // invoke existing contract
        await this.invokeSetSecret(currentProof, nextProofHash, secret, this.$getKTAddress());
        return;
      }

      
      // create new contract
      var initialNonce = this.$randInt();
      const hash = true;
      const initialHashedProof = this.$generateProof(
        this.$store.state.private_key,
        initialNonce.toString(),
        hash
      );
      
      const contract = await this.$deployContract(initialNonce, initialHashedProof, true);

      if (contract.status != 'applied') {
        this.$bvToast.toast(
          "Failed to contact tezos node, try again.",
          {
            title: "Adding Secret  ...",
            variant: "danger",
            solid: true
          }
        );

        return;
      }

      console.log(contract);

      this.$setKTAddress(contract.originated_contracts);

      const currentProof = this.$generateProof(this.$store.state.private_key, initialNonce.toString());

      const nextProofHash = this.$generateProof(this.$store.state.private_key, (++initialNonce).toString(), hash);

      const results = await this.invokeSetSecret(currentProof, nextProofHash, secret, contract.originated_contracts);
      console.log(results);

    }
  }
};
</script>


<style scoped>
</style>
