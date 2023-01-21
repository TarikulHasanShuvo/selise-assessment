export default [
    {
        path: '/',
        name: 'Home',
        component: () => import('./pages/Home'),
        meta: {
            title: 'Home'
        }
    },
    {
        path: '/login',
        name: 'Login',
        component: () => import('./auth/Login'),
        meta: {
            title: 'Login'
        }
    },
    {
        path: '/register',
        name: 'Register',
        component: () => import('./auth/Register'),
        meta: {
            title: 'Register'
        }
    }
];
