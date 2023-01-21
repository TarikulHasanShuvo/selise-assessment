const ACCESS_TOKEN      = "selise_access_token";
const REFRESH_TOKEN     = 'selise_refresh_token';
const EXPIRE_AT         = 'expires_at';

export const getToken = () => {
    return window.localStorage.getItem(ACCESS_TOKEN);
};

export const saveToken = (token,refresh_token) => {
    window.localStorage.setItem(ACCESS_TOKEN, token);
    window.localStorage.setItem(REFRESH_TOKEN, refresh_token);
};

export const destroyToken = () => {
    window.localStorage.removeItem(ACCESS_TOKEN);
    window.localStorage.removeItem(REFRESH_TOKEN);
    window.localStorage.removeItem(EXPIRE_AT);
};

export default {getToken, saveToken, destroyToken};
