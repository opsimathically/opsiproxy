/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable no-debugger */
/* eslint-disable no-empty */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-unused-vars */

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% OpsiProxySocketContext Class %%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/*
All contexts use this class as a base context.  This is created
by the opsiproxy net server, and is associated with the original
socket connection.
*/

import { randomGuid } from '@opsimathically/randomdatatools';
import { Deferred, DeferredMap } from '@opsimathically/deferred';
import { deepEqual } from 'node:assert';
import { EventEmitter } from 'node:stream';
import http from 'node:http';

import {
  OpsiHTTPProxy,
  opsiproxy_socket_i,
  opsiproxy_plugin_t
} from '@src/proxies/http/proxy';

import {
  OpsiProxyContext,
  opsiproxy_context_position_indicator_t
} from '@src/proxies/http/contexts/OpsiProxyContext.class';

type opsiproxy_net_context_options_t = {
  parent_ctx: OpsiProxyContext;
  proxy: OpsiHTTPProxy;
  socket: opsiproxy_socket_i;
  position: opsiproxy_context_position_indicator_t;
};

interface opsiproxy_http_incomming_message_i extends http.IncomingMessage {
  parsed_request_url: URL;
  parsed_host_header: {
    host: string;
    port: number;
  };
  host_and_port?: {
    host: string;
    port: number;
  };
}

interface opsiproxy_http_proxy_to_client_response_message_i
  extends http.ServerResponse<http.IncomingMessage> {
  req: opsiproxy_http_incomming_message_i;
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

// type opsiproxy_https_mitm_handles_t = {};

type http_regular_request_handles_t = {
  client_to_proxy_socket?: opsiproxy_socket_i;
  client_to_proxy_request?: opsiproxy_http_incomming_message_i;
  proxy_server_to_client_response?: opsiproxy_http_proxy_to_client_response_message_i;
  proxy_to_remote_server_socket?: opsiproxy_socket_i;
  proxy_to_remote_server_request?: opsiproxy_http_incomming_message_i;
  remote_server_to_proxy_response?: opsiproxy_http_proxy_to_client_response_message_i;
};

type http_connect_request_handles_t = {
  client_to_proxy_socket?: opsiproxy_socket_i;
  client_to_proxy_request?: opsiproxy_http_incomming_message_i;
  proxy_server_to_client_response?: opsiproxy_http_proxy_to_client_response_message_i;
  proxy_to_remote_server_socket?: opsiproxy_socket_i;
  proxy_to_remote_server_request?: opsiproxy_http_incomming_message_i;
  remote_server_to_proxy_response?: opsiproxy_http_proxy_to_client_response_message_i;
};

class OpsiProxySocketContext extends EventEmitter {
  uuid: string;

  // mark as a socket context
  type: string = 'socket_ctx';

  position: opsiproxy_context_position_indicator_t = 'unknown';

  parent_ctx: OpsiProxyContext;
  opsiproxy_ref!: OpsiHTTPProxy;

  // determines context type
  context_type: 'connect' | 'regular' | 'unset' = 'unset';

  // define regular request handles, they will be assigned as context
  // stages progress.
  http_regular_request_handles: http_regular_request_handles_t = {
    client_to_proxy_socket: null as unknown as opsiproxy_socket_i,
    client_to_proxy_request:
      null as unknown as opsiproxy_http_incomming_message_i,
    proxy_server_to_client_response:
      null as unknown as opsiproxy_http_proxy_to_client_response_message_i,
    proxy_to_remote_server_socket: null as unknown as opsiproxy_socket_i,
    proxy_to_remote_server_request:
      null as unknown as opsiproxy_http_incomming_message_i,
    remote_server_to_proxy_response:
      null as unknown as opsiproxy_http_proxy_to_client_response_message_i
  };

  // define connect request handles, they will be assigned as context
  http_connect_request_handles: http_connect_request_handles_t = {
    client_to_proxy_socket: null as unknown as opsiproxy_socket_i,
    client_to_proxy_request:
      null as unknown as opsiproxy_http_incomming_message_i,
    proxy_server_to_client_response:
      null as unknown as opsiproxy_http_proxy_to_client_response_message_i,
    proxy_to_remote_server_socket: null as unknown as opsiproxy_socket_i,
    proxy_to_remote_server_request:
      null as unknown as opsiproxy_http_incomming_message_i,
    remote_server_to_proxy_response:
      null as unknown as opsiproxy_http_proxy_to_client_response_message_i
  };

  // Proxy can handle two 'request' types, a normal one, and a CONNECT
  // one.  SSL requests are handled by the CONNECT request type. Non-SSL
  // requests are handled, typically, by the 'request' type.
  // Based on the request type, we will have different sets of handles,
  // because the nature of the request types differ.

  // plugin activation log
  plugin_activations: plugin_activation_info_t = {};
  plugin_activation_history: string[] = [];

  // proxy stage
  stage: string[] = [];

  // TODO: rename this, will have to be changed to a more context
  // specific name
  socket!: opsiproxy_socket_i;

  deferred_map: DeferredMap = new DeferredMap();

  // ssl specifier
  isSSL: boolean = false;

  // http event markers
  http_events: { [key: string]: boolean } = {};
  http_events_history: string[] = [];

  server_to_proxy_response!: any;
  proxy_to_server_request_options!: any;
  proxy_to_server_request!: any;
  connect_request!: any;
  client_to_proxy_request!: opsiproxy_http_incomming_message_i;
  proxy_to_client_response!: any;
  response_content_potentially_modified: boolean = false;

  dest_host_and_port!: { host: string; port: number };

  options: opsiproxy_net_context_options_t;

  constructor(options: opsiproxy_net_context_options_t) {
    super();

    // preserve options
    this.options = options;

    // set position
    this.position = options.position;

    // set uuids
    this.uuid = randomGuid();
    this.options.socket.uuid = this.uuid;

    // set parent context
    this.parent_ctx = options.parent_ctx;

    // set contexts in socket so we can easily get their handles from the
    // net/http server parameters.  This is primarily how we get handles to
    // contexts in server callbacks.
    options.socket.parent_ctx = options.parent_ctx;
    options.socket.socket_ctx = this;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Socket Pause Controls %%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  socketIsPaused() {
    const ctx_ref = this;
    if (ctx_ref.options.socket.readableFlowing) return false;
    return true;
  }

  pauseSocket() {
    const ctx_ref = this;
    if (ctx_ref.socketIsPaused()) return false;
    ctx_ref.options.socket.pause();
    return true;
  }

  resumeSocket() {
    const ctx_ref = this;
    if (!ctx_ref.socketIsPaused()) return false;
    ctx_ref.options.socket.resume();
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Old Old Old %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

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
        host: parsed_host_as_url.hostname,
        port: parseInt(parsed_host_as_url.port)
      };
    } catch (err) {}
    if (!req?.parsed_host_header?.host) return false;
    if (!req?.parsed_host_header?.port) return false;
    return true;
  }

  async parseURLStringAsHostAndPortOnly(host_port_str: string) {
    let host = '';
    let port = -1;
    try {
      const split_str = host_port_str.split(':');
      host = split_str[0];
      port = parseInt(split_str[1]);
    } catch (err) {}
    return {
      host: host,
      port: port
    };
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

  parseRequestHostAndPort(req: opsiproxy_http_incomming_message_i): boolean {
    if (!req.url) return false;

    let url: URL = null as unknown as URL;

    if (typeof req.url !== 'string') return false;
    if (req.url.startsWith('http')) {
      try {
        url = new URL(req.url);
      } catch (e) {}
    } else {
      try {
        url = new URL(`http://${req.url}`);
      } catch (e) {}
    }
    if (!url) return false;

    const hostname = url.hostname;
    let port = url.port ? parseInt(url.port, 10) : undefined;

    if (!port) {
      // Default ports based on scheme
      switch (url.protocol) {
        case 'http:':
          port = 80;
          break;
        case 'https:':
          port = 443;
          break;
        default:
          debugger;
          throw new Error(
            `No port specified and unknown protocol: ${url.protocol}`
          );
      }
    }

    // set host and port
    req.host_and_port = {
      host: hostname,
      port: port
    };

    // return indicating success
    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% client_to_proxy_request Methods %%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async client_to_proxy_requestTerminate(
    reason: string,
    http_status_code: number
  ) {
    const ctx_ref = this;
    if (!ctx_ref.client_to_proxy_request)
      throw new Error('client_to_proxy_request_is_unset');

    if (ctx_ref.client_to_proxy_requestIsPaused())
      ctx_ref.client_to_proxy_request.resume();

    ctx_ref.client_to_proxy_request.resume();
    ctx_ref.proxy_to_client_response.writeHead(http_status_code, {
      'Content-Type': 'text/html; charset=utf-8'
    });
    ctx_ref.proxy_to_client_response.end(reason, 'utf-8');
    return;
  }

  /**
   * When a request starts, it must be paused so that information can be gathered, this
   * simply checks to see if the request is in the paused state or not.
   */
  client_to_proxy_requestIsPaused() {
    const ctx_ref = this;
    if (!ctx_ref.client_to_proxy_request)
      throw new Error('client_to_proxy_request_is_unset');

    if (!ctx_ref.client_to_proxy_request.readableFlowing) return false;
    return true;
  }
}

export {
  OpsiProxySocketContext,
  opsiproxy_net_context_options_t,
  opsiproxy_http_incomming_message_i,
  opsiproxy_http_proxy_to_client_response_message_i
};
