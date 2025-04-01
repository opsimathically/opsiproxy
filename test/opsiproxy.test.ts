/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import test from 'node:test';
import assert from 'node:assert';
import { deepEqual } from 'fast-equals';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';

import {
  OpsiHTTPProxy,
  opsiproxy_options_t,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_t
} from '@src/proxies/http/proxy';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Utilities %%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

async function makeProxiedRequest(
  method: 'GET' | 'POST',
  path: string,
  proxy_host: string,
  proxy_port: number,
  target_host: string,
  target_port: number,
  data?: string
): Promise<string> {
  return new Promise((resolve, reject) => {
    const target_url = `http://${target_host}:${target_port}${path}`;

    const req_options: http.RequestOptions = {
      host: proxy_host,
      port: proxy_port,
      method,
      path: target_url,
      headers: {
        Host: `${target_host}:${target_port}`
      }
    };

    if (method === 'POST' && data) {
      req_options.headers = {
        ...req_options.headers,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      };
    }

    const req = http.request(req_options, (res) => {
      let response_data = '';

      res.on('data', (chunk) => {
        response_data += chunk;
      });

      res.on('end', () => {
        resolve(response_data);
      });
    });

    req.on('error', (err) => {
      reject(err);
    });

    if (method === 'POST' && data) {
      req.write(data);
    }

    req.end();
  });
}

class TestHttpProxyPlugin implements opsiproxy_plugin_t {
  info: opsiproxy_plugin_info_t = {
    name: 'test_http_proxy_plugin',
    description: 'Test proxy plugins.'
  };

  constructor() {}

  /*
  async onError() {}
  async onConnect() {}
  async onRequestHeaders() {}
  async onRequest() {}
  async onWebSocketConnection() {}
  async onWebSocketSend() {}
  async onWebSocketMessage() {}
  async onWebSocketFrame() {}
  async onWebSocketClose() {}
  async onWebSocketError() {}
  async onRequestData() {}
  async onRequestEnd() {}
  async onResponse() {}
  async onResponseHeaders() {}
  async onResponseData() {}
  async onResponseEnd() {}
  */
}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

(async function () {
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% OpsiHTTPProxy Tests %%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
        const parsedUrl = new URL(url);
        if (method === 'GET' && parsedUrl.pathname === '/gethere') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end('HI!');
          return;
        }

        if (method === 'POST' && parsedUrl.pathname === '/posthere') {
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

    const post_result = await makeProxiedRequest(
      'POST',
      '/posthere',
      '127.0.0.1',
      8080,
      '127.0.0.1',
      dummy_server_listen_port,
      JSON.stringify({ hello: 'there' })
    );

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Close Servers %%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    await opsihttpproxy.close();
    server.close();
  });
})();
