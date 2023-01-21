<template>
  <div class="container">
    <NavBar/>
    <router-view></router-view>
  </div>
</template>

<script>

import NavBar from "@/views/public/layouts/NavBar";

export default {
  name: "AuthLayout",
  components: {NavBar},
}
</script>

<style scoped>

</style>
