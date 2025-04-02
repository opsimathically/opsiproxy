/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-debugger */
/* eslint-disable no-empty */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { randomGuid } from '@opsimathically/randomdatatools';
import { Deferred, DeferredMap } from '@opsimathically/deferred';
import { deepEqual } from 'node:assert';
import http from 'node:http';

import {
  OpsiHTTPProxy,
  opsiproxy_socket_i,
  opsiproxy_plugin_t
} from '@src/proxies/http/proxy';

interface opsiproxy_http_incomming_message_i extends http.IncomingMessage {
  parsed_request_url: URL;
  parsed_host_header: {
    host: string;
    port: number;
  };
}

type plugin_activation_info_t = {
  [key: string]: {
    [key: string]: {
      end: boolean;
      continue: boolean;
      handled: boolean;
      noop: boolean;
    };
  };
};

class OpsiproxyRequestContext {
  opsiproxy_ref!: OpsiHTTPProxy;
  plugin_activations: plugin_activation_info_t = {};
  plugin_activation_history: string[] = [];
  socket!: opsiproxy_socket_i;
  deferred_map: DeferredMap = new DeferredMap();
  uuid!: string;
  isSSL: boolean = false;
  http_events: { [key: string]: boolean } = {};
  http_events_history: string[] = [];
  serverToProxyResponse!: any;
  proxyToServerRequestOptions!: any;
  proxyToServerRequest!: any;
  connectRequest!: any;
  clientToProxyRequest!: opsiproxy_http_incomming_message_i;
  proxyToClientResponse!: any;
  responseContentPotentiallyModified!: boolean;

  constructor() {}

  // end the context (behavior depends on http event state)
  async end(params: any) {
    debugger;
  }

  setHttpEventFlag(event_name: string, val: boolean) {
    const ctx_ref = this;
    ctx_ref.http_events[event_name] = val;
    ctx_ref.http_events_history.push(`${event_name}:${val}`);
    return true;
  }

  setPluginEventFlag(
    plugin: opsiproxy_plugin_t,
    event_name: string,
    val: string
  ) {
    const ctx_ref = this;

    // plugin.info.name
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Request Parsers %%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async parseRequestHostHeader(req: opsiproxy_http_incomming_message_i) {
    if (!req?.headers?.host) return false;
    try {
      const parsed_host_as_url: URL = new URL('http://' + req.headers.host);
      req.parsed_host_header = {
        host: parsed_host_as_url.host,
        port: parseInt(parsed_host_as_url.port)
      };
    } catch (err) {}
    if (!req?.parsed_host_header?.host) return false;
    if (!req?.parsed_host_header?.port) return false;
    return true;
  }

  async parseRequestURL(req: opsiproxy_http_incomming_message_i) {
    if (!req.url) {
      return false;
    }
    try {
      req.parsed_request_url = new URL(req.url);
    } catch (err) {}
    if (!req?.parsed_request_url) return false;
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% clientToProxyRequest Methods %%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async clientToProxyRequestTerminate(
    reason: string,
    http_status_code: number
  ) {
    const ctx_ref = this;
    if (!ctx_ref.clientToProxyRequest)
      throw new Error('client_to_proxy_request_is_unset');

    if (ctx_ref.clientToProxyRequestIsPaused())
      ctx_ref.clientToProxyRequest.resume();

    ctx_ref.clientToProxyRequest.resume();
    ctx_ref.proxyToClientResponse.writeHead(http_status_code, {
      'Content-Type': 'text/html; charset=utf-8'
    });
    ctx_ref.proxyToClientResponse.end(reason, 'utf-8');
    return;
  }

  /**
   * When a request starts, it must be paused so that information can be gathered, this
   * simply checks to see if the request is in the paused state or not.
   */
  clientToProxyRequestIsPaused() {
    const ctx_ref = this;
    if (!ctx_ref.clientToProxyRequest)
      throw new Error('client_to_proxy_request_is_unset');

    if (!ctx_ref.clientToProxyRequest.readableFlowing) return false;
    return true;
  }
}

export { OpsiproxyRequestContext, opsiproxy_http_incomming_message_i };
