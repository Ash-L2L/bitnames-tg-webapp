const path = require('path')

module.exports = {
    entry: 'web/index.js',
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: 'bundle.js',
    },
  };