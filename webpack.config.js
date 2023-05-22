const path = require('path');
const webpack = require('webpack');

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
    plugins: [
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
        }),
    ],
    resolve: {
        fallback: {
            buffer: require.resolve('buffer/'),
            crypto: require.resolve("crypto-browserify/"),
            path: require.resolve("path-browserify/"),
            stream: require.resolve("stream-browserify/"),
        },
    },
  };