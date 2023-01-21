import { createRouter, createWebHistory } from 'vue-router'
import NotFound from '../components/PageNotFound';

import PublicRoutes  from "@/views/public/_routes";
import PublicLayout  from "@/views/public/layouts/Layout";

//Auth Section
import PrivateRoutes  from "@/views/protected/_routes";
import AuthLayout  from "@/views/protected/Layout";


const routes = [
  //========== Public Routes routing==========

  {
    path     : '/',
    component: PublicLayout,
    children : PublicRoutes
  },


  //========== Private Routes routing==========
  {
    path     : '/',
    component: AuthLayout,
    children : PrivateRoutes,
    meta     : {
      requireAuth: true,
    }
  },
  //==========404  routing==========
  {
    path: '/:pathMatch(.*)*',
    name     : 'Not Found',
    component: NotFound,
    meta     : {
      title: 'Not Found'
    }
  },

]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
