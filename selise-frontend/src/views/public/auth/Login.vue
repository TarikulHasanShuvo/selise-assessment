<template>
  <div class="container d-flex justify-content-center">
    <div class="col-6 card mt-5 shadow">
      <div class="card-header">
        <h2 class="text-center">Login</h2>
      </div>
      <div class="card-body">
        <form @submit.prevent="login()">
          <div class="mb-3">
            <label for="exampleInputEmail1" class="form-label">Email address</label>
            <input v-model="loginInfo.email" type="email" class="form-control" id="exampleInputEmail1"
                   aria-describedby="emailHelp" required>
          </div>
          <div class="mb-5">
            <label for="exampleInputPassword1" class="form-label">Password</label>
            <input v-model="loginInfo.password" type="password" class="form-control" id="exampleInputPassword1"
                   required>
          </div>
          <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <div class="d-flex justify-content-center mt-5">
          <h6 class="text-muted">New Member ?</h6>
          <router-link to="/register" class="text-primary ms-2"><h6>Register</h6></router-link>
        </div>
        <div class="mt-4">
          <h5>Credentials</h5>
          <hr>
          <p @click="setValue" class="text-muted"><b>Email :</b> admin@gmail.com</p>
          <p @click="setValue" class="text-muted"><b>Password :</b> 12345678</p>
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
  name: "Login",
  mixins: [ToastMessage],
  data: () => ({
    loginInfo: {
      email: "",
      password: "",
    },
  }),
  methods: {
    login() {
      ApiService.post('/login', this.loginInfo).then(({data}) => {
        console.log('data', data);
        if (data.status === 200) {
          JwtService.saveToken(data.access_token,data.refresh_token);
          ApiService.init();
          this.$store.commit("STORE_USER", data.user);
          this.toastMessage('Login Successfully');
          this.$router.push({name: "Dashboard"});
        } else {
          this.toastMessage(data.message, 'error');
        }
      }).catch((errors) => {
        this.toastMessage(errors.response.data.message, 'error');
      });
    },
    setValue() {
      this.loginInfo.email = 'admin@gmail.com'
      this.loginInfo.password = '12345678'
    }
  }
};
</script>
