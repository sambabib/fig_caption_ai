const path = require('path');
const Dotenv = require('dotenv-webpack');
const webpack = require('webpack');
const fs = require('fs');  // For reading ui.html
const dotenv = require('dotenv'); // For direct loading of env vars

module.exports = (env) => {
  const isProduction = env.production === true;
  // Determine which .env file to use based on --env flag
  const envPath = isProduction ? '.env.production' : '.env.development';
  
  // Load environment variables directly
  const envVars = dotenv.config({ path: envPath }).parsed || {};
  console.log('Loaded environment variables:', Object.keys(envVars));
  
  // Ensure critical variables are available
  const apiUrl = envVars.API_URL || 'http://localhost:5000';
  const pluginSecret = envVars.PLUGIN_SECRET || '';

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
        systemvars: true, // load all system variables
        defaults: false,  // don't load .env.defaults
      }),
      new webpack.DefinePlugin({
        'NODE_ENV': JSON.stringify(isProduction ? 'production' : 'development'),
        // Use the directly loaded variables
        'API_URL': JSON.stringify(apiUrl),
        'PLUGIN_SECRET': JSON.stringify(pluginSecret),
        '__html__': JSON.stringify(fs.readFileSync('./ui.html', 'utf8'))
      }),
    ],
  };
};
