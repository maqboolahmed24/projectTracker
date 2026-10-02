import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
export default {
  output:'standalone', outputFileTracingRoot:resolve(fileURLToPath(new URL('..',import.meta.url))), poweredByHeader:false,
  reactStrictMode:true, devIndicators:false,
  webpack(config){config.resolve.extensionAlias={'.js':['.ts','.tsx','.js'],'.mjs':['.mts','.mjs']};return config;},
  experimental:{proxyClientMaxBodySize:'24mb'},
  async headers(){return [{source:'/:path*',headers:[
    {key:'X-Content-Type-Options',value:'nosniff'}, {key:'Referrer-Policy',value:'no-referrer'},
    {key:'Permissions-Policy',value:'camera=(), microphone=(), geolocation=()'},
    {key:'X-Frame-Options',value:'DENY'}
  ]}];}
};
