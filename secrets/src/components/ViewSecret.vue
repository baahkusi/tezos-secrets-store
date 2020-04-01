<template>
  <div role="tablist">
    <b-card no-body class="mb-3" v-for="(s, i) in secrets" :key="i">
      <b-card-header header-tag="header" class="p-1" role="tab">
        <b-list-group class="m-3">
          <b-list-group-item href="#">{{s.description}}</b-list-group-item>
        </b-list-group>
        <b-button href="#" v-b-toggle="'accordion-'+i" variant="primary" class="m-3">Reveal Secret</b-button>
      </b-card-header>
      <b-collapse :id="'accordion-'+i" :accordion="'my-accordion-'+i" role="tabpanel">
        <b-card-body>
          <b-card-text>
            <p>{{ s.secret }}</p>
            <b-button href="#" variant="success">Copy Secret</b-button>
          </b-card-text>
        </b-card-body>
      </b-collapse>
    </b-card>
    <b-button variant="primary" class="mt-3" @click="fetchData">Fetch Secrets</b-button>
  </div>
</template>

<script>
export default {
  data() {
    return {
      secrets: []
    };
  },
  methods: {
    async fetchData(){
      if (this.secrets.length > 0) {
        return;
      }
      this.$store.state.msg = 'Fetching your secret data from smart contract, this could take a minute. ...';
      this.$store.state.show = true;
      if (!this.$store.state.authed) {
        this.$bvToast.toast(
          "You need to provide your auth credentials first.",
          {
            title: "Fetching Secrets  ...",
            variant: "danger",
            solid: true
          }
        );
        this.$store.state.show = false;
        return;
      }

      if (this.$getKTAddress() && this.$store.state.private_key) {
       const secrets = await this.$getSecrets(this.$getKTAddress());
        try {
          this.secrets = secrets.map((secret)=>this.$decryptData(secret, this.$store.state.private_key));
        } catch (error) {
          this.$bvToast.toast(
          "Incorrect credentials provided for contract.",
          {
            title: "Fetching Secrets  ...",
            variant: "danger",
            solid: true
          }
        );
        }
       
      }

      this.$store.state.show = false;
    }
  },
};
</script>