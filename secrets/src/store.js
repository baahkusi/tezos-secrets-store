


const sstore = {
    state:{
        username:'',
        password:'',
        private_key:'',
        authed:false,
        show:false,
        msg:'Please wait ...'
    },
    mutations:{
        set_auth(state, auth){
            state.username = auth.username,
            state.password = auth.password,
            state.private_key = auth.private_key
            state.authed = true;
        }
    }
};

export default sstore;