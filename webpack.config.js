const path = require('path')

module.exports = {
    entry: {
        index: './web/index.js',
        decrypt: './web/decrypt.js',
    },
    mode: 'development',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].bundle.js',
    },
    resolve: {
        fallback: {
            buffer: require.resolve('buffer/'),
            crypto: require.resolve("crypto-browserify/"),
            stream: require.resolve("stream-browserify/"),
        },
    },
  };