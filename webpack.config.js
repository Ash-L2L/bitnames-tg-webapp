const path = require('path')

module.exports = {
    entry: './web/index.js',
    mode: 'development',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: 'bundle.js',
    },
    resolve: {
        fallback: {
            buffer: require.resolve('buffer/'),
            crypto: require.resolve("crypto-browserify/"),
            stream: require.resolve("stream-browserify/"),
        },
    },
  };