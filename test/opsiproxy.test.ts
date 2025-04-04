/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import test from 'node:test';
import assert from 'node:assert';
import { deepEqual } from 'fast-equals';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';

import axios, { AxiosResponse } from 'axios';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { HttpProxyAgent } from 'http-proxy-agent';

import { OpsiProxySocketContext } from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';

import {
  OpsiHTTPProxy,
  opsiproxy_options_t,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_t,
  opsiproxy_plugin_method_ret_t
} from '@src/proxies/http/proxy';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

async function makeProxiedRequest(params: {
  proxy_url: string;
  request_url: string;
  method: 'GET' | 'POST';
  data: any;
}): Promise<AxiosResponse> {
  let response: AxiosResponse;

  /*
  // parse url and select agent based on protocol
  const parsed_request_url = new URL(params.request_url);
  let https_agent = new HttpsProxyAgent(params.proxy_url);
  switch (parsed_request_url.protocol) {
    case 'http:':
      agent = new HttpProxyAgent(params.proxy_url);
      break;
    case 'https:':
      agent = new HttpsProxyAgent(params.proxy_url);
      break;
    default:
      return null as unknown as AxiosResponse;
  }
  */

  switch (params.method) {
    case 'GET':
      response = await axios.get(params.request_url, {
        proxy: {
          protocol: 'http',
          host: '127.0.0.1',
          port: 8080
        }
      });
      return response;

    case 'POST':
      response = await axios.post(params.request_url, params.data, {
        proxy: {
          protocol: 'http',
          host: '127.0.0.1',
          port: 8080
        },
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        }
      });
      return response;
      break;
    default:
      break;
  }

  return null as unknown as AxiosResponse;
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Proxy Plugins %%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

class TestHttpProxyPlugin implements opsiproxy_plugin_t {
  info: opsiproxy_plugin_info_t = {
    name: 'test_http_proxy_plugin',
    description: 'Test proxy plugins.'
  };

  constructor() {}

  async net_proxy__client_to_proxy__initial_connection(
    ctx: OpsiProxySocketContext
  ): Promise<opsiproxy_plugin_method_ret_t> {
    // debugger;

    const ret_data: opsiproxy_plugin_method_ret_t = {
      behavior: 'noop'
    };
    return ret_data;
  }
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

(async function () {
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% OpsiHTTPProxy Tests %%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /*
  test('Test ca directory must be valid.', async function () {
    const test_http_proxy_plugin = new TestHttpProxyPlugin();
    const opsihttpproxy = new OpsiHTTPProxy({
      host: 'localhost',
      httpPort: 8080,
      sslCaDir: path.resolve(__dirname, 'test_ca_dir'),
      keepAlive: true,
      timeout: 0,
      httpAgent: new http.Agent({ keepAlive: true }),
      httpsAgent: new https.Agent({ keepAlive: true }),
      forceSNI: false,
      httpsPort: 8081,
      forceChunkedRequest: false,
      plugins: [test_http_proxy_plugin]
    });

    try {
      await opsihttpproxy.listen();
    } catch (err) {
      if (err instanceof Error) {
        assert(err.message === 'opsiproxy_ssl_ca_dir_is_invalid');
      }
    }
    await opsihttpproxy.close();
  });
  */
  test('Test opsiproxy with http request.', async function () {
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Create Dummy HTTP Server %%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const server = http.createServer(
      (req: http.IncomingMessage, res: http.ServerResponse) => {
        const { method, url } = req;
        if (typeof url !== 'string') {
          res.end('Not found');
          return;
        }

        if (method === 'GET' && url === '/gethere') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('HI!');
          return;
        }

        if (method === 'POST' && url === '/posthere') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ hello: 'there' }));
          return;
        }
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      }
    );

    // set dummy server listen port
    const dummy_server_listen_port: number = 38383;
    await new Promise(function (resolve, reject) {
      server.listen(dummy_server_listen_port, () => {
        resolve(true);
      });
    });

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Create Proxy %%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const test_http_proxy_plugin = new TestHttpProxyPlugin();
    const opsihttpproxy = new OpsiHTTPProxy({
      host: 'localhost',
      httpPort: 8080,
      sslCaDir: path.resolve(__dirname, 'test_ca_dir'),
      keepAlive: true,
      timeout: 0,
      httpAgent: new http.Agent({ keepAlive: true }),
      httpsAgent: new https.Agent({ keepAlive: true }),
      forceSNI: false,
      httpsPort: 8081,
      forceChunkedRequest: false,
      plugins: [test_http_proxy_plugin]
    });

    await opsihttpproxy.listen();

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Make Dummy Request %%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    const proxy_get_response = await makeProxiedRequest({
      proxy_url: 'http://127.0.0.1:8080',
      request_url: `http://127.0.0.1:${dummy_server_listen_port}/gethere`,
      method: 'GET',
      data: null
    });

    console.log(proxy_get_response.data);
    debugger;
    /*

    const https_response = await makeProxiedRequest({
      proxy_url: 'http://127.0.0.1:8080',
      request_url: `https://old.reddit.com/`,
      method: 'GET',
      data: null
    });

    console.log(https_response.data);
    debugger;

     */
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Close Servers %%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    await opsihttpproxy.close();
    server.close();
  });
})();
