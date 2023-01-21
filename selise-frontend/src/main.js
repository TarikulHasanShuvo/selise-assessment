import { createApp,nextTick  } from 'vue'
import App from './App.vue'
import './registerServiceWorker'
import router from './router'
import store from './store'
import '../src/scss/main.scss';
import 'bootstrap';
import ApiService from "@/services/api.service";
import VueSweetalert2 from 'vue-sweetalert2';
import 'sweetalert2/dist/sweetalert2.min.css';
import AuthCheckService from "@/services/auth.check.service";
ApiService.init();
AuthCheckService.checkAuth();



createApp(App).use(store).use(router).use(VueSweetalert2).mount('#app')
