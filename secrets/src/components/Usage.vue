<template>
  <b-list-group>
    <b-list-group-item variant="light" class="flex-column align-items-start">
      <div class="d-flex w-100 justify-content-between">
        <h5 class="mb-1 text-primary">About</h5>
      </div>

      <p
        class="mb-1"
      >The purpose of this application is to allow users to store secrets 
      (could be anything from mnemnics to private keys ..) using a username and password.
       <a href="https://medium.com/ejara/storing-retrieving-secrets-on-a-public-smart-contract-925f02178d7">Refere to this medium article for indepth explanation.</a>
      </p>
      <small class="text-primary"></small>
    </b-list-group-item>
    <b-list-group-item variant="light" class="flex-column align-items-start">
      <div class="d-flex w-100 justify-content-between">
        <h5 class="mb-1 text-primary">Auth</h5>
      </div>

      <p class="mb-1">
        The first step is to provide Authentication credenitials (username and password).
        <span
          class="text-danger"
        >
          <b-icon icon="circle-fill" small></b-icon> Auth
        </span> means the application does not have your Auth credentials yet.
        <span class="text-success">
          <b-icon icon="circle-fill" small></b-icon> Auth
        </span> means the application has your Auth credentials.
      </p>
      <small class="text-primary">Use the same credenitials everytime</small>
    </b-list-group-item>
    <b-list-group-item variant="light" class="flex-column align-items-start">
      <div class="d-flex w-100 justify-content-between">
        <h5 class="mb-1 text-primary">Add Secret</h5>
      </div>

      <p
        class="mb-1"
      >The Add Secret section is where you can enter the information you want to keep secret. This information is encrypted and stored on the smart contract.</p>
    </b-list-group-item>
    <b-list-group-item variant="light" class="flex-column align-items-start">
      <div class="d-flex w-100 justify-content-between">
        <h5 class="mb-1 text-primary">View Secrets</h5>
      </div>

      <p
        class="mb-1"
      >This section allows you to retreive and view all secrets you have stored on the smart contract.</p>
    </b-list-group-item>
  </b-list-group>
</template>

<script>
export default {};
</script>