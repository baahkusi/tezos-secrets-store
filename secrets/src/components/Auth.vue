<template>
  <div>
    <b-form @submit="onSubmit">
      <b-form-group id="input-username" label="User Name:" label-for="username" description>
        <b-form-input id="username" v-model="form.username" type="text" required placeholder></b-form-input>
      </b-form-group>

      <b-form-group id="input-password" label="Password:" label-for="password">
        <b-form-input id="password" v-model="form.password" type="password" required placeholder></b-form-input>
      </b-form-group>

      <b-form-group id="input-confirm" label="Confirm Password:" label-for="confirm">
        <b-form-input id="confirm" v-model="form.confirm" type="password" required placeholder></b-form-input>
      </b-form-group>

      <b-button type="submit" variant="primary">Submit</b-button>
    </b-form>
  </div>
</template>

<script>
import { mapMutations } from "vuex";
export default {
  data() {
    return {
      form: {
        username: "",
        password: "",
        confirm: ""
      }
    };
  },
  methods: {
    ...mapMutations(["set_auth"]),
    onSubmit(evt) {
      evt.preventDefault();
      if (this.form.password !== this.form.confirm) {
        alert("Passwords Dont Match.");
        return false;
      }
      // alert(JSON.stringify(this.form));
      // Generate private_key username and password

      this.$store.state.msg = 'Generating secret key from credentials, this could take a minute or three. ...';
      this.$store.state.show = true;
      this.$toKey(this.form.password.trim(), this.form.username.trim())
        .then(h => {
          const auth = {
            private_key: h.hashHex,
            username: this.form.username,
            password: this.form.password
          };

          this.$store.state.show = false;
          this.set_auth(auth);
          this.$bvToast.toast(
            "Secret Key Generation Done. Now you can perform the other operations.",
            {
              title: "Generating secret key from password  ...",
              variant: "success",
              solid: true
            }
          );
        })
        .catch((e) => {
          this.$bvToast.toast("something went wrong :(.", {
            title: "Generating secret key from password  ...",
            variant: "danger",
            solid: true
          });
          console.log(e);
        });
    }
  }
};
</script>


<style scoped>
</style>
