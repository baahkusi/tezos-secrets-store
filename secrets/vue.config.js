module.exports = {
    configureWebpack: {
      module: {
        noParse: /\.wasm$/,
        rules: [
            {
                test: /\.wasm$/,
                loaders: ['base64-loader'],
                type: 'javascript/auto'
            }
        ]
    }
    }
  }