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

      

      const dataCipher = this.$encryptData(
        JSON.stringify(this.form),
        this.$store.state.private_key,
      );

      console.log(dataCipher);      

      if (this.$getKTAddress()) {
        
        // get current nonce
        // generate current proof
        // generate next proofHash
        // invoke existing contract
        return;
      }

      
      // create new contract
      const initialNonce = this.$randInt();
      const hash = true;
      const initialHashedProof = this.$generateProof(
        this.$store.state.private_key,
        initialNonce.toString(),
        hash
      );
      
      const contract = await this.$deployContract(initialNonce.toString(), initialHashedProof);

      console.log(contract);

    }
  }
};
</script>


<style scoped>
</style>
