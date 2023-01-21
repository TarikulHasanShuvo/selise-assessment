<template>
  <nav id="navbar" class="navbar navbar-expand-lg mt-3 px-3">
    <div class="container">
      <router-link to="/" class="navbar-brand" href="#">Selise Assessment</router-link>
      <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
        <span class="navbar-toggler-icon"></span>
      </button>
      <div class="collapse navbar-collapse" id="navbarSupportedContent">
        <ul v-if="Object.keys($store.state.user).length" class="navbar-nav me-auto mb-2 mb-lg-0">
          <li class="nav-item">
            <router-link to="/dashboard" class="nav-link" :class="{'active': $route.name == 'Dashboard'}" aria-current="page" href="#">Home</router-link>
          </li>
        </ul>
          <h6 v-if="Object.keys($store.state.user).length" class="me-3">Hi, {{ $store.state.user?.name  }}</h6>
          <button @click="logout" v-if="Object.keys($store.state.user).length" class="btn btn-secondary">Logout</button>
         <div v-else class="ms-auto">
           <router-link to="login" class="btn btn-outline-success">Login</router-link>
         </div>
      </div>
    </div>
  </nav>
</template>

<script>
import ApiService from "@/services/api.service";
import JwtService from "@/services/jwt.service";
import ToastMessage from "@/mixins/ToastMessage";
export default {
  name: "NavBar",
  mixins: [ToastMessage],

  methods : {
    logout() {
        ApiService.post('/logout').then(res => {
          JwtService.destroyToken();
          this.$store.commit("STORE_USER", {});
          this.toastMessage('Logout Successfully');
          this.$router.push('/');
        }).catch(error => {
          this.toastMessage(error.response.data.message,'error');
        })
      },
    }
}
</script>

<style lang="scss" scoped>
.active {
  color: #842b43 !important;
  font-weight: bold;
}
</style>
