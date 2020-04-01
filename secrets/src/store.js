


const sstore = {
    state:{
        username:'',
        password:'',
        private_key:'',
        authed:false,
        show:false,
        msg:'Please wait ...',
        kt:''
    },
    mutations:{
        set_auth(state, auth){
            state.username = auth.username,
            state.password = auth.password,
            state.private_key = auth.private_key
            state.authed = true;
        }
    },
    getters:{
        address(state){
            if (state.kt) {
                return state.kt;
            }

            return localStorage.getItem('KTAddress');
        }
    }
};

export default sstore;