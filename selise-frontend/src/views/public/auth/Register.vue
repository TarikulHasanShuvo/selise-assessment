<template>
  <div class="container">
    <div class="row">
      <div class="col-sm-8 m-auto ">
        <div class="card m-5">
          <div class="card-header">
            <h2 class="text-center"> Registration</h2>
          </div>
          <div class="card-body">
            <form @submit.prevent="registration" class="mb-5">
              <div class="mb-3">
                <label for="name" class="form-label">Full Name</label>
                <input type="text" class="form-control" id="name"
                       v-model="form.name" required>
              </div>

              <div class="mb-3">
                <label for="email" class="form-label">Email address</label>
                <input type="email" class="form-control" id="email" aria-describedby="emailHelp"
                       v-model="form.email" required>
              </div>
              <div class="mb-3">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" v-model="form.password" required>
              </div>

              <div class="mt-5">
                <button class="btn btn-primary w-100" type="submit">Sign Up</button>
              </div>

              <div class="pt-5">
                <p class="text-center"> Already Have an account?
                  <router-link to="/login" href="">Login</router-link>
                </p>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script>


import ApiService from "@/services/api.service";
import JwtService from "@/services/jwt.service";
import ToastMessage from "@/mixins/ToastMessage";
export default {
  name: "Register",
  mixins: [ToastMessage],
  data() {
    return {
      form: {}
    }
  },
  methods: {
    registration() {
      ApiService.post('/registration', this.form).then(({data}) => {
        JwtService.saveToken(data.access_token);
        ApiService.init();
        this.$store.commit("STORE_USER", data.user);
        this.toastMessage('Registration Successfully');
        this.$router.push({name: "Home"});
      }).catch((error) => {
        this.toastMessage( error.response.data.message,'error');
      });
    },
  }

}
</script>
