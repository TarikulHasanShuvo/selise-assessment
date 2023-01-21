
const webRoutes = [
    {
        path: '/dashboard',
        name: 'Dashboard',
        component: () => import('./pages/dashboard/Dashboard.vue'),
        meta: {
            title: 'Dashboard'
        }
    }
];

export default webRoutes;
