const path = require('path');
const Dotenv = require('dotenv-webpack');
const webpack = require('webpack');
const fs = require('fs');  // For reading ui.html

module.exports = (env) => {
  const isProduction = env.production === true;
  // Determine which .env file to use based on --env flag
  const envPath = isProduction ? '.env.production' : '.env.development';

  return {
    mode: env.production ? 'production' : 'development',
    entry: './code.ts',
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/,
        }
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
    },
    output: {
      filename: 'code.js',
      path: path.resolve(__dirname, './'),
      library: {
        type: 'window'
      }
    },
    plugins: [
      new Dotenv({
        path: envPath,
        systemvars: true // load all system variables
      }),
      new webpack.DefinePlugin({
        'NODE_ENV': JSON.stringify(isProduction ? 'production' : 'development'),
        'API_URL': JSON.stringify(process.env.API_URL),
        '__html__': JSON.stringify(fs.readFileSync('./ui.html', 'utf8'))
      }),
    ],
  };
};
