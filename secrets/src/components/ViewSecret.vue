<template>
  <div role="tablist">
    <b-card no-body class="mb-3" v-for="(s, i) in secrets" :key="i">
      <b-card-header header-tag="header" class="p-1" role="tab">
        <b-list-group class="m-3">
          <b-list-group-item href="#">Description of Secret</b-list-group-item>
        </b-list-group>
        <b-button href="#" v-b-toggle="'accordion-'+i" variant="primary" class="m-3">Reveal Secret</b-button>
      </b-card-header>
      <b-collapse :id="'accordion-'+i" :accordion="'my-accordion-'+i" role="tabpanel">
        <b-card-body>
          <b-card-text>
            <p>{{ text }}</p>
            <b-button href="#" variant="success">Copy Secret</b-button>
          </b-card-text>
        </b-card-body>
      </b-collapse>
    </b-card>
    <b-button variant="primary" class="mt-3" @click="secrets ++">Fetch Secrets</b-button>
  </div>
</template>

<script>
export default {
  data() {
    return {
      secrets: 0,
      text: `
          Anim pariatur cliche reprehenderit, enim eiusmod high life accusamus terry
          richardson ad squid. 3 wolf moon officia aute, non cupidatat skateboard dolor
          brunch. Food truck quinoa nesciunt laborum eiusmod. Brunch 3 wolf moon
          tempor, sunt aliqua put a bird on it squid single-origin coffee nulla
          assumenda shoreditch et. Nihil anim keffiyeh helvetica, craft beer labore
          wes anderson cred nesciunt sapiente ea proident. Ad vegan excepteur butcher
          vice lomo. Leggings occaecat craft beer farm-to-table, raw denim aesthetic
          synth nesciunt you probably haven't heard of them accusamus labore VHS.
        `
    };
  }
};
</script>