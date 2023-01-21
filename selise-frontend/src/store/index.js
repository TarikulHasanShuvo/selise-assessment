import {createStore} from 'vuex'

export default createStore({
    state: {
        user: {},
    },

    getters: {
        getCurrentUser(state) {
            return state.user
        },
    },

    mutations: {
        STORE_USER(state, payload) {
            state.user = payload
        },
    },
    actions: {},
    modules: {}
})
