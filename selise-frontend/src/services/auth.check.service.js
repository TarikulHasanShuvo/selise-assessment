import router from "@/router";
import * as JwtService from "@/services/jwt.service";
import ApiService from "@/services/api.service";
import store from "@/store";
import {nextTick} from "vue";

const AuthCheckService ={
    checkAuth(){
        router.beforeEach((to, from, next) => {
            if (to.matched.some(record => record.meta.requireAuth)) {
                if (!JwtService.getToken()) {
                    next({
                        name  : 'Login',
                        params: {nextUrl: to.fullPath}
                    })
                }
                else {
                    ApiService.get('/check-token').then(response => {
                        store.commit("STORE_USER", response.data.user);
                        next()
                    }).catch(error => {
                        JwtService.destroyToken();
                        next({name: 'Login'})
                    })
                }
            }
            if (to.name == 'Login') {
                if (JwtService.getToken()) {
                    next({name: 'Dashboard'});
                }
            }
            nextTick(() => {
                document.title = `${to.meta.title}`;
            })
            next();
        });
    },

};

export default AuthCheckService;