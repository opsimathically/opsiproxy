/* eslint-disable no-debugger */
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

import crytpo from 'crypto';

import { Deferred } from '@opsimathically/deferred';

import net from 'node:net';

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

import { OpsiProxyMITMHttpsServer } from '@src/proxies/http/mitm_servers/https/OpsiProxyMITMHttpsServer.class';

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
  type: string = 'tunnel_ctx_ref';
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
    const tunnel_ctx_ref = this;

    // ensure socket is paused
    if (
      !tunnel_ctx_ref.options.client_to_proxy.request.socket_context.socketIsPaused()
    ) {
      tunnel_ctx_ref.options.client_to_proxy.request.socket_context.pauseSocket();
    }

    if (tunnel_ctx_ref?.options?.client_to_proxy?.request?.connect?.encrypted) {
    }

    // gather host and port
    const host = tunnel_ctx_ref?.options?.client_to_proxy?.request?.host;
    if (!host) return null;
    const port = tunnel_ctx_ref?.options?.client_to_proxy?.request?.port;
    if (!port) return null;

    const mitm_server_hash = crytpo
      .createHash('sha1')
      .update(`${host}:${port}`)
      .digest('hex');

    // check if we already have a proxy ready
    const http_mitm_proxy =
      tunnel_ctx_ref.options.proxy.mitm_server_map.get(mitm_server_hash);

    const parent_ctx = tunnel_ctx_ref.options.parent_ctx;

    // gather client to proxy socket context
    const client_to_proxy_socket_ctx =
      parent_ctx.sub_contexts.client_to_proxy.socket_ctx;

    if (!client_to_proxy_socket_ctx?.options.socket) return false;

    const opsiproxy_ref = parent_ctx.options.proxy;

    debugger;

    // if there is no matching proxy, go ahead and create and register a new one
    if (!http_mitm_proxy) {
      // if this is a https tunnel, we need to create a new mitm server
      if (
        tunnel_ctx_ref?.options?.client_to_proxy?.request?.connect?.encrypted
      ) {
        debugger;

        const http_mitm_proxy = new OpsiProxyMITMHttpsServer({
          tunnel_ctx: tunnel_ctx_ref,
          hosts: [host],
          port: port
        });

        // http_mitm_proxy.addr_info.address;
        // http_mitm_proxy.addr_info.port;

        debugger;
        // start the mitm proxy server
        await http_mitm_proxy.start();

        const net_connect_deferred: Deferred = new Deferred();
        const client_to_mitm_proxy_connection = net.connect(
          {
            port: http_mitm_proxy.addr_info.port,
            host: http_mitm_proxy.addr_info.address,
            allowHalfOpen: true
          },
          () => {
            // handle close events on both sockets
            client_to_mitm_proxy_connection.on('close', () => {
              // params.client_socket.destroy();
              debugger;
            });
            client_to_proxy_socket_ctx?.options.socket.on('close', () => {
              // client_to_mitm_proxy_connection.destroy();
              debugger;
            });

            // handle error events on both sockets
            client_to_mitm_proxy_connection.on('error', () => {
              // params.client_socket.destroy();
              debugger;
            });
            client_to_proxy_socket_ctx?.options.socket.on('error', () => {
              // client_to_mitm_proxy_connection.destroy();
              debugger;
            });

            // pipe the client socket through the mitm socket
            // and vice versa.  I think we can use an async generator here
            // to control packet traversals.
            client_to_proxy_socket_ctx?.options.socket.pipe(
              client_to_mitm_proxy_connection
            );
            client_to_mitm_proxy_connection.pipe(
              client_to_proxy_socket_ctx?.options.socket
            );

            // emit data to the client socket
            client_to_proxy_socket_ctx?.options.socket.emit(
              'data',
              tunnel_ctx_ref.options.client_to_proxy.request.head
            );
            client_to_proxy_socket_ctx?.options.socket.resume();

            net_connect_deferred.resolve(true);
          }
        );

        await net_connect_deferred.promise;
      }

      /*

    // create or get private key and cert for this host
    const mitm_certs = await opsiproxy_ref.getHTTPsMITMCertificates(ctx);

    // check certificates
    if (!mitm_certs.cert_pem.length || !mitm_certs.private_key_pem)
      throw new Error('could_not_create_mitm_certificates');

    const https_server_options: https.ServerOptions = {
      key: mitm_certs.private_key_pem,
      cert: mitm_certs.cert_pem
    };

    const https_mitm_server = https.createServer(https_server_options);
      */
    }

    debugger;
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
