<template>
  <div id="app">
    <b-overlay :show="$store.state.show" spinner-type="grow" spinner-variant="primary">
    <div>
      <h1 class="text-center pb-3"><i>Secrets Store - Demo.</i></h1>
      <b-tabs content-class="m-5" class="m-5" justified>
        <b-tab title="Usage" active>
          Usage
        </b-tab>
        <b-tab title="Auth">
          <Auth />
        </b-tab>
        <b-tab title="Add Secret">
          <AddSecret />
        </b-tab>
        <b-tab title="View Secrets">
          <ViewSecret />
        </b-tab>
      </b-tabs>
    </div>
    </b-overlay>
  </div>
</template>

<script>
import Auth from "./components/Auth.vue";
import AddSecret from "./components/AddSecret.vue";
import ViewSecret from "./components/ViewSecret.vue";

export default {
  name: "App",
  components: {
    Auth,
    AddSecret,
    ViewSecret
  }
};
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  /* text-align: center; */
  color: #2c3e50;
  margin-top: 60px;
}
</style>
