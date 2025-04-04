/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable no-empty */
/* eslint-disable @typescript-eslint/no-unused-vars */
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% OpsiProxyTunnelContextProcessor Class %%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/*
HTTP Proxies use either forward requests, or tunnels.  This class
handles the context in which a tunnel is made.
*/

import {
  OpsiHTTPProxy,
  opsiproxy_socket_i,
  opsiproxy_http_incomming_message_i,
  opsiproxy_plugin_t
} from '@src/proxies/http/proxy';

import {
  OpsiProxyContext,
  opsiproxy_context_position_indicator_t
} from '@src/proxies/http/contexts/OpsiProxyContext.class';

import { OpsiProxySocketContext } from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';
import { EventEmitter } from 'stream';

/*
type opsiproxy_net_context_options_t = {
  parent_ctx: OpsiProxyContext;
  proxy: OpsiHTTPProxy;
  socket: opsiproxy_socket_i;
  position: opsiproxy_context_position_indicator_t;
};
*/

type opsiproxy_tunnel_context_options_t = {
  parent_ctx: OpsiProxyContext;
  proxy: OpsiHTTPProxy;
  position: opsiproxy_context_position_indicator_t;
  client_to_proxy: {
    request: {
      socket_context: OpsiProxySocketContext;
      message: opsiproxy_http_incomming_message_i;
      head: Buffer;
      host?: string; // parsed on new
      port?: number; // parsed on new
      connect?: {
        encrypted: boolean;
      };
    };
  };
  indicators?: {
    tls_detected: boolean;
  };
};

class OpsiProxyTunnelContext extends EventEmitter {
  type: string = 'tunnel_ctx';
  options: opsiproxy_tunnel_context_options_t;

  constructor(options: opsiproxy_tunnel_context_options_t) {
    super();
    this.options = options;

    // always immediately pause the socket
    // always pause the socket on init
    this.options.client_to_proxy.request.socket_context.pauseSocket();

    // host and port must be parsable
    const client_to_proxy_request_host_and_port = this.parseRequestHostAndPort(
      this.options.client_to_proxy.request?.message
    );
    if (!client_to_proxy_request_host_and_port)
      return null as unknown as OpsiProxyTunnelContext;

    // set host and port
    this.options.client_to_proxy.request.host =
      client_to_proxy_request_host_and_port.host;
    this.options.client_to_proxy.request.port =
      client_to_proxy_request_host_and_port.port;

    // detect tls/ssl
    options.client_to_proxy.request.connect = {
      encrypted: this.detectTLSFromRequestHead(
        options.client_to_proxy.request.head
      )
    };
  }

  // start the context processor
  async start() {
    // set self reference
    const tunnel_ctx = this;

    // ensure socket is paused
    if (
      !tunnel_ctx.options.client_to_proxy.request.socket_context.socketIsPaused()
    ) {
      tunnel_ctx.options.client_to_proxy.request.socket_context.pauseSocket();
    }
  }

  detectTLSFromRequestHead(head: Buffer) {
    if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {
      return true;
    }
    return false;
  }

  parseRequestHostAndPort(
    req: opsiproxy_http_incomming_message_i
  ): { host: string; port: number } | null {
    if (!req.url) return null;

    let url: URL = null as unknown as URL;

    if (typeof req.url !== 'string') return null;
    if (req.url.startsWith('http')) {
      try {
        url = new URL(req.url);
      } catch (e) {}
    } else {
      try {
        url = new URL(`http://${req.url}`);
      } catch (e) {}
    }
    if (!url) return null;

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
          throw new Error(
            `No port specified and unknown protocol: ${url.protocol}`
          );
      }
    }

    // return indicating success
    return {
      host: hostname,
      port: port
    };
  }
}

export { OpsiProxyTunnelContext, opsiproxy_tunnel_context_options_t };
