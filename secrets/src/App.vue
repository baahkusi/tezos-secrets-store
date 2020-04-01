<template>
  <div id="app" class="mt-4">
    <b-overlay :show="$store.state.show" spinner-type="grow" spinner-variant="primary">
      <div>
        <div class="text-center">
          <p v-if="$store.getters.address"> Explore contract at 
            <a :href="kt" target="blank">
            {{kt}}
            </a>
          </p>
          <b-img src="./assets/logo.png" alt="Ejara Logo" fluid></b-img>
          <h1 class="text-primary">Secrets Store - Demo.</h1>
        </div>
        <b-tabs content-class="m-5" class="mt-4" justified>
          <b-tab title="Usage" active>
            <template v-slot:title><b>Usage</b></template>
            <Usage />
          </b-tab>
          <b-tab title="Auth">
            <template v-slot:title>
              <span :class="authed"><b><b-icon icon="circle-fill" small></b-icon> Auth</b></span>
            </template>
            <Auth />
          </b-tab>
          <b-tab title="Add Secret">
            <template v-slot:title><b>Add Secret</b></template>
            <AddSecret />
          </b-tab>
          <b-tab title="View Secrets">
            <template v-slot:title><b>View Secrets</b></template>
            <ViewSecret />
          </b-tab>
        </b-tabs>
      </div>
      <template v-slot:overlay>
        <div class="text-center">
          <b-icon icon="stopwatch" font-scale="3" animation="cylon"></b-icon>
          <p id="cancel-label">{{$store.state.msg}}</p>
        </div>
      </template>
    </b-overlay>
  </div>
</template>

<script>
import Auth from "./components/Auth.vue";
import Usage from "./components/Usage.vue";
import AddSecret from "./components/AddSecret.vue";
import ViewSecret from "./components/ViewSecret.vue";

export default {
  name: "App",
  components: {
    Auth,
    Usage,
    AddSecret,
    ViewSecret
  },
  computed: {
    authed(){
      return this.$store.state.authed ? 'text-success':'text-danger';
    },
    kt(){
      return `https://better-call.dev/carthage/${this.$store.getters.address}/operations`
    }
  },
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  /* text-align: center; */
  color: #2c3e50;
}
</style>
