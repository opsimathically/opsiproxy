/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Intercept HTTP/HTTPs Requests Using Plugin %%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

import test from 'node:test';
import assert from 'node:assert';
import { deepEqual } from 'fast-equals';
import path from 'node:path';
import http from 'node:http';
import https from 'node:https';

import axios, { AxiosResponse } from 'axios';
import { HttpsProxyAgent } from 'https-proxy-agent';
import { HttpProxyAgent } from 'http-proxy-agent';

import { OpsiProxyNetContext } from '@src/proxies/http/contexts/OpsiProxyNetContext.class';

import {
  OpsiHTTPProxy,
  opsiproxy_options_t,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_t,
  opsiproxy_plugin_method_ret_t
} from '@src/proxies/http/proxy';

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
    ctx: OpsiProxyNetContext
  ): Promise<opsiproxy_plugin_method_ret_t> {
    // debugger;

    const ret_data: opsiproxy_plugin_method_ret_t = {
      behavior: 'noop'
    };
    return ret_data;
  }
}

(async function () {
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

  // await opsihttpproxy.close();
})();
