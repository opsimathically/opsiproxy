/* eslint-disable no-debugger */
/* eslint-disable no-empty */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-explicit-any */

import { randomGuid } from '@opsimathically/randomdatatools';
import IterAsync from '@opsimathically/iterasync';
import { Deferred, DeferredMap } from '@opsimathically/deferred';
import {
  OpsiProxyNetContext,
  opsiproxy_http_incomming_message_i,
  opsiproxy_http_proxy_to_client_response_message_i
} from '@src/proxies/http/contexts/OpsiProxyNetContext.class';

import {
  OpsiProxyPluginRunner,
  opsiproxy_plugin_runner_run_info_t,
  opsiproxy_plugin_activation_t,
  opsiproxy_plugin_runner_routable_label_info_t
} from '@src/proxies/http/plugin_runner/OpsiProxyPluginRunner.class';

import { constants } from 'fs';
import { access } from 'fs/promises';
import * as fs_promises from 'fs/promises';
import async from 'async';
import type { AddressInfo } from 'net';
import net from 'net';

import type {
  Server as HTTPServer,
  IncomingHttpHeaders,
  IncomingMessage,
  ServerResponse
} from 'http';
import http from 'http';
import type { Server, ServerOptions } from 'https';
import https from 'https';
import fs from 'fs';
import path from 'path';
import type { WebSocket as WebSocketType } from 'ws';
import WebSocket, { WebSocketServer } from 'ws';

import url from 'url';
import semaphore from 'semaphore';
import ca from './ca';
import { ProxyFinalResponseFilter } from './ProxyFinalResponseFilter';
import { ProxyFinalRequestFilter } from './ProxyFinalRequestFilter';
import { v4 as uuid } from 'uuid';

import gunzip from './middleware/gunzip';
import wildcard from './middleware/wildcard';
import type {
  ICertDetails,
  IContext,
  IProxy,
  IProxyOptions,
  ErrorCallback,
  ICertficateContext,
  ICreateServerCallback,
  IProxySSLServer,
  IWebSocketContext,
  OnCertificateRequiredCallback,
  OnConnectParams,
  OnErrorParams,
  OnRequestDataParams,
  OnRequestParams,
  OnWebSocketCloseParams,
  OnWebSocketErrorParams,
  OnWebSocketFrameParams,
  OnWebSocketMessageParams,
  OnWebsocketRequestParams,
  OnWebSocketSendParams,
  IWebSocketCallback,
  OnRequestDataCallback
} from './types';
import type stream from 'node:stream';
import { SecureContextOptions } from 'tls';
export { wildcard, gunzip };

type opsiproxy_plugin_info_t = {
  name: string;
  description: string;
};

/**
 * The return data from a plugin event handler.  It is instrumental in determining
 * how the proxy will behave with regards to context.
 */
type opsiproxy_plugin_method_ret_t = {
  /**
   * terminate_context:
   * Will end the context, destroying it entirely, stopping any further
   * continuance.
   *
   * continue:
   * Asserts that the plugin has interacted with the context at this stage, but instructs to continue
   * passing the context to the next plugin.
   *
   * go_next_stage:
   * Indicates that the plugin interacted with the context, and instructs the context to move to
   * the next stage in the proxying process.
   *
   * stop_at_this_stage:
   * Will stop at this stage, assuming that the plugin will handle the rest of the stages
   * itself.  Will not destroy the context, but will not progress further in stages.
   *
   * handled:
   * Asserts that the plugin has handled this stage of the connection/request.  No more
   * plugins will be called, and it is assumed that the plugin will be handling the remainder
   * of any and all stages.  For example, if a request is handled by a plugin, the proxy will
   * not forward the request, will not end the request, and will simply assume that the context
   * is handled by the plugin from there on.
   *
   * noop: (no operation)
   * The plugin had a relevant event handler present, and it was executed, but it did
   * not affect the context at all.  Will proceed to the next plugin.
   */
  behavior:
    | 'terminate_context'
    | 'continue_to_next_plugin'
    | 'handled'
    | 'noop'
    | 'go_next_stage'
    | 'stop_at_this_stage';
};

type opsiproxy_plugin_event_cb_t = (
  ctx: OpsiProxyNetContext
) => Promise<opsiproxy_plugin_method_ret_t>;

type opsiproxy_plugin_t = {
  info: opsiproxy_plugin_info_t;

  net_proxy__client_to_proxy__initial_connection?: opsiproxy_plugin_event_cb_t;
};

type HandlerType<T extends (...args: any[]) => any> = Array<Parameters<T>[0]>;
interface WebSocketFlags {
  mask?: boolean | undefined;
  binary?: boolean | undefined;
  compress?: boolean | undefined;
  fin?: boolean | undefined;
}

interface opsiproxy_websocket_i extends WebSocket {
  upgradeReq?: IncomingMessage;
}

interface opsiproxy_socket_i extends net.Socket {
  uuid?: string;
  deferral?: Deferred;
  opsiproxy_net_ctx?: OpsiProxyNetContext;
}

type opsiproxy_options_t = {
  // net.BlockList for incomming proxy connections (people connecting to the proxy)
  proxy_incomming_block_list?: net.BlockList;
  // net.BlockList for outgoing requests that the proxy itself makes.
  proxy_outgoing_block_list?: net.BlockList;
  // The port or named socket to listen on (default: 8080).
  httpPort: number;
  // The hostname or local address to listen on.
  host: string;
  // Path to the certificates cache directory (default: process.cwd() + '/.http-mitm-proxy')
  sslCaDir: string;
  // enable HTTP persistent connection
  keepAlive: boolean;
  // The number of milliseconds of inactivity before a socket is presumed to have timed out. Defaults to no timeout.
  timeout: number;
  // The http.Agent to use when making http requests. Useful for chaining proxys. (default: internal Agent)
  httpAgent: http.Agent;
  // The https.Agent to use when making https requests. Useful for chaining proxys. (default: internal Agent)
  httpsAgent: https.Agent;
  // force use of SNI by the client. Allow node-http-mitm-proxy to handle all HTTPS requests with a single internal server.
  forceSNI: boolean;
  // The port or named socket for https server to listen on. (forceSNI must be enabled)
  httpsPort: number;
  // Setting this option will remove the content-length from the proxy to server request, forcing chunked encoding
  forceChunkedRequest: boolean;
  // Proxy plugins.
  plugins: opsiproxy_plugin_t[];
};

type mitm_server_certs_t = {
  cert_pem: Buffer;
  private_key_pem: Buffer;
};

type mitm_server_set_t = {
  hostname: string;
  listening_port: number;
  mitm_certs: mitm_server_certs_t;
  https_mitm_server: any;
  webscoket_mitm_server: any;
};

type http_headers_t = Record<string, string>;
/**
 * My History With This Project:
 * About six months back I didn't know typescript well.  As a result I took this entire project and mostly
 * ported it to javascript to utilize for my own internal security testing tools.  It worked well, but
 * eventually I came to my senses and learned typescript.  Now with that new knowledge I want to approach
 * this excellent minded project and retrofit my javascript changes and subsystems into a public version
 * of my existing tooling.
 *
 * Change notes:
 * Due to changes in libraries, common coding practices, and my own personal desires I'll be modifying
 * this file fairly drastically.  I have several goals in mind:
 *
 * REQUIRED CHANGES:
 * ------------------------
 * Change:
 * ws.upgradeReq no longer exists.  It was deemed insecure.  We need to as a result, extend a type from
 * WebSocket and utilize that, so that upgradeReq can be preserved.
 *
 * Change:
 * Update/remove callback additions.  My idea for these would be we define a plugin that
 * contains some or all of the following.  These would be executed on a context matching
 * method.
 *
 * [] onError
 * [] onConnect
 * [] onRequestHeaders
 * [] onRequest
 * [] onWebSocketConnection
 * [] onWebSocketSend
 * [] onWebSocketMessage
 * [] onWebSocketFrame
 * [] onWebSocketClose
 * [] onWebSocketError
 * [] onRequestData
 * [] onRequestEnd
 * [] onResponse
 * [] onResponseHeaders
 * [] onResponseData
 * [] onResponseEnd
 *
 * Change:
 * Update handlers to be more typed, extended with new features.
 * [] onConnectHandlers
 * [] onRequestHandlers
 * [] onRequestHeadersHandlers
 * [] onWebSocketConnectionHandlers
 * [] onWebSocketFrameHandlers
 * [] onWebSocketCloseHandlers
 * [] onWebSocketErrorHandlers
 * [] onErrorHandlers
 * [] onRequestDataHandlers
 * [] onRequestEndHandlers
 * [] onResponseHandlers
 * [] onResponseHeadersHandlers
 * [] onResponseDataHandlers
 * [] onResponseEndHandlers
 *
 * PERSONAL DESIRED CHANGES
 * ------------------------
 * Desired Change:
 * All relevant callbacks should be asynchronous/awaited on.
 *
 * Why:
 * My interests in this project are to utilize it as an investigative/collection/security testing tool.  That means
 * that a lot of data comparissons will have to be made with backends such as databases.  For example,
 * checking if a database record exists and terminating or modifying a request/response based on the contents
 * of that database record.  This is easily done with async/await, but not so much with synchronous callbacks.
 *
 * Desired Change:
 * A more robust plugin system.
 *
 * Why:
 * To integrate multiple tools and systems based on proxy context.
 *
 */

class OpsiHTTPProxy {
  /*
  // These are found within the options set, and appear to have 
  // been duplicated.
  forceSNI!: boolean;
  httpAgent!: http.Agent;
  httpHost?: string;
  httpPort!: number;
  httpsAgent!: https.Agent;
  httpsPort?: number;
  keepAlive!: boolean;
  sslCaDir!: string;
  timeout!: number;

  // opsiproxy plugins
  plugins: opsiproxy_plugin_t[] = [];
  */

  // node-http-proxy-plugins (old)
  static wildcard = wildcard;
  static gunzip = gunzip;

  // plugin runner
  plugin_runner: OpsiProxyPluginRunner = new OpsiProxyPluginRunner();

  // certficate authority
  ca!: ca;

  // connection requests
  connect_requests: Record<string, http.IncomingMessage> = {};

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Tracking Maps %%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // a map of all request contexts
  context_map: Map<string, OpsiProxyNetContext> = new Map<
    string,
    OpsiProxyNetContext
  >();

  // map of all mitm servers
  mitm_server_map: Map<string, mitm_server_set_t> = new Map<
    string,
    mitm_server_set_t
  >();

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Proxy Servers %%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /**
   * This server handles all socket requests from proxy clients, forwarding
   * them into the httpServer.  It's necessary because if we just use http
   * servers directly, we cannot capture and pause initial socket states
   * for plugins to operate/handle.
   */
  netServer!: net.Server;

  /**
   * Main http proxy server.
   */
  httpServer!: http.Server;

  /**
   * Investigating if it's necessary.  I'd rather just use stunnel
   * to handle encryption between points instead of having two different
   * proxy implementations, especially since node tls isn't exactly perfectly
   * fast.
   */
  httpsServer!: https.Server;

  options!: opsiproxy_options_t;

  // not sure what this is used for; wouldn't this be relevant only
  // in a context?
  response_content_potentially_modified: boolean;

  sslSemaphores: Record<string, semaphore.Semaphore> = {};
  sslServers: Record<string, IProxySSLServer> = {};

  wsServer: WebSocketServer | undefined;
  wssServer: WebSocketServer | undefined;

  constructor(options: opsiproxy_options_t) {
    this.options = options;
    /*
    this.onConnectHandlers = [];
    this.onRequestHandlers = [];
    this.onRequestHeadersHandlers = [];
    this.onWebSocketConnectionHandlers = [];
    this.onWebSocketFrameHandlers = [];
    this.onWebSocketCloseHandlers = [];
    this.onWebSocketErrorHandlers = [];
    this.onErrorHandlers = [];
    this.onRequestDataHandlers = [];
    this.onRequestEndHandlers = [];
    this.onResponseHandlers = [];
    this.onResponseHeadersHandlers = [];
    this.onResponseDataHandlers = [];
    this.onResponseEndHandlers = [];
    */
    this.response_content_potentially_modified = false;
  }

  async start() {
    // create https proxy server
    // create http proxy server
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% File/Directory Utilities %%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // checks if a file exists and is readable
  async fileExistsAndIsReadable(f: string): Promise<boolean> {
    try {
      const resolved_file = path.resolve(f);
      const stats = await fs_promises.stat(resolved_file);
      if (!stats.isFile()) return false;
      await fs_promises.access(resolved_file, constants.R_OK);
      return true;
    } catch {
      return false;
    }
  }

  // check if directory exists and is writable
  async isWritableDirectory(p: string): Promise<boolean> {
    try {
      const resolvedPath = path.resolve(p);
      const stats = await fs_promises.stat(resolvedPath);
      if (!stats.isDirectory()) return false;
      await fs_promises.access(resolvedPath, constants.W_OK);
      return true;
    } catch {
      return false;
    }
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Context Management %%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // create a new context
  async createNetContext(
    socket: opsiproxy_socket_i
  ): Promise<OpsiProxyNetContext> {
    const opsiproxy_ref = this;

    // set socket uuid on connection
    socket.uuid = randomGuid();

    // create new context and immediately pause the request
    const ctx = new OpsiProxyNetContext();
    socket.opsiproxy_net_ctx = ctx;
    ctx.stage.push('client_to_proxy__connection');
    ctx.opsiproxy_ref = opsiproxy_ref;
    ctx.socket = socket;
    ctx.uuid = socket.uuid;
    ctx.setHttpEventFlag('connection', true);

    // add context to the context map
    opsiproxy_ref.context_map.set(ctx.uuid, ctx);
    ctx.setHttpEventFlag('context_added_to_map', true);
    return ctx;
  }

  // Destroy context
  async destroyContext(ctx: OpsiProxyNetContext) {
    const opsiproxy_ref = this;

    // remove the context from the map
    // and destroy the socket associated.
    opsiproxy_ref.context_map.delete(ctx.uuid);
    ctx.socket.destroy();

    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Start Listener %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async listen() {
    // set self reference
    const opsiproxy_ref = this;

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Certificate Authority %%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // always ensure the ca directory exists
    if (
      !(await opsiproxy_ref.isWritableDirectory(opsiproxy_ref.options.sslCaDir))
    )
      throw new Error('opsiproxy_ssl_ca_dir_is_invalid');

    // create the ca
    const ca_deferral: Deferred = new Deferred();
    ca.create(
      opsiproxy_ref.options.sslCaDir,
      (err: Error | null | undefined, ca: ca) => {
        if (err) {
          throw err;
          return;
        }
        ca_deferral.resolve(ca);
      }
    );
    opsiproxy_ref.ca = await ca_deferral.promise;

    opsiproxy_ref.sslServers = {};
    opsiproxy_ref.sslSemaphores = {};
    opsiproxy_ref.connect_requests = {};

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Net/HTTP Proxy Servers %%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    opsiproxy_ref.httpServer = new http.Server();
    opsiproxy_ref.httpServer.timeout = opsiproxy_ref.options.timeout;

    // create server
    opsiproxy_ref.netServer = net.createServer({
      /*pauseOnConnect: true,*/
      blockList: opsiproxy_ref.options.proxy_incomming_block_list
    });

    /*
    ,
      async (socket) => {
        debugger;
        // socket.resume();
        opsiproxy_ref.httpServer.emit('connection', socket);
      }
    */

    // ensure servers were created ok
    if (!opsiproxy_ref.netServer)
      throw new Error('opsiproxy_could_not_create_net_server');
    if (!opsiproxy_ref.httpServer)
      throw new Error('opsiproxy_could_not_create_proxy_http_server');

    // setup event handlers
    await opsiproxy_ref.setupNetProxyServerEventHandlers();
    await opsiproxy_ref.setupHttpProxyServerEventHandlers();
    await opsiproxy_ref.setupHttpProxyWebsocketServerEventHandlers();

    // start the net server
    const deferral: Deferred = new Deferred();
    opsiproxy_ref.netServer.listen(
      {
        host: opsiproxy_ref.options.host,
        port: opsiproxy_ref.options.httpPort
      },
      () => {
        deferral.resolve(true);
      }
    );
    return await deferral.promise;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% TLS/SSL Detection %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /*
   * Detect TLS from first bytes of data
   * Inspired from https://gist.github.com/tg-x/835636
   * used heuristic:
   * - an incoming connection using SSLv3/TLSv1 records should start with 0x16
   * - an incoming connection using SSLv2 records should start with the record size
   *   and as the first record should not be very big we can expect 0x80 or 0x00 (the MSB is a flag)
   * - everything else is considered to be unencrypted
   */
  detectTLSFromRequestHead(head: Buffer) {
    if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {
      return true;
    }
    return false;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% HTTPs MITM Server Methods %%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async getHTTPsMITMCertificates(
    ctx: OpsiProxyNetContext
  ): Promise<mitm_server_certs_t> {
    // set self reference
    const opsiproxy_ref = this;

    // ensure we have a host
    if (!ctx?.client_to_proxy_request?.host_and_port?.host)
      return null as unknown as mitm_server_certs_t;

    const hostname = ctx.client_to_proxy_request.host_and_port.host;

    const keypath = path.join(
      opsiproxy_ref.options.sslCaDir,
      'keys',
      hostname,
      '.key'
    );
    const certpath = path.join(
      opsiproxy_ref.options.sslCaDir,
      'certs',
      hostname,
      '.pem'
    );

    // pems
    let cert_pem: Buffer = Buffer.from('');
    let private_key_pem: Buffer = Buffer.from('');

    // ensure both key and cert are readable
    const key_is_readable =
      await opsiproxy_ref.fileExistsAndIsReadable(keypath);
    const cert_is_readable =
      await opsiproxy_ref.fileExistsAndIsReadable(certpath);

    // gather pems if they exist
    if (key_is_readable && cert_is_readable) {
      cert_pem = await fs_promises.readFile(certpath);
      private_key_pem = await fs_promises.readFile(keypath);
    }

    // if the key isn't readable, or cert isn't readable, we need to create the certs
    else if (!key_is_readable || !cert_is_readable) {
      const hosts = [hostname];
      const cert_deferred: Deferred = new Deferred();
      opsiproxy_ref.ca.generateServerCertificateKeys(
        hosts,
        (certPEM: any, privateKeyPEM: any) => {
          cert_pem = certPEM;
          private_key_pem = privateKeyPEM;
          cert_deferred.resolve(true);
        }
      );
      await cert_deferred.promise;
    }

    if (!cert_pem || !private_key_pem)
      throw new Error('failed_to_create_or_load_certificates');

    // return pems
    return {
      cert_pem: cert_pem,
      private_key_pem: private_key_pem
    };
  }

  // This method will create a MITM server using our own certificate authority
  // suitable for proxying connections.
  async createHTTPsMITMServer(
    ctx: OpsiProxyNetContext
  ): Promise<mitm_server_set_t> {
    // set self reference
    const opsiproxy_ref = this;

    if (!ctx.client_to_proxy_request.host_and_port) {
      return null as unknown as mitm_server_set_t;
    }

    // gather hostname
    const hostname = ctx.client_to_proxy_request.host_and_port.host;

    // if we already have a proxy ready, go ahead and return it immediately
    const existing_proxy_set = opsiproxy_ref.mitm_server_map.get(hostname);
    if (existing_proxy_set) return existing_proxy_set;

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

    https_mitm_server.on('error', async (err: Error) => {
      debugger;
    });

    https_mitm_server.on(
      'clientError',
      async (err: Error, socket: opsiproxy_socket_i) => {
        debugger;
      }
    );

    https_mitm_server.on(
      'connect',
      (req: IncomingMessage, socket: stream.Duplex, head: Buffer) => {
        debugger;
      }
    );

    https_mitm_server.on(
      'request',
      (
        // req: IncomingMessage,
        // res: ServerResponse<IncomingMessage> & { req: IncomingMessage }
        client_to_proxy_request: opsiproxy_http_incomming_message_i,
        proxy_to_client_response: opsiproxy_http_proxy_to_client_response_message_i
      ) => {
        const ctx = (client_to_proxy_request.socket as opsiproxy_socket_i)
          .opsiproxy_net_ctx;
        if (!ctx) throw new Error('request_with_no_context_is_unreasonable');

        if (!client_to_proxy_request?.host_and_port?.host) return;
        if (!client_to_proxy_request?.host_and_port?.port) return;
        /*
        ctx_ref.proxy_to_client_response.writeHead(http_status_code, {
          'Content-Type': 'text/html; charset=utf-8'
        });
        ctx_ref.proxy_to_client_response.end(reason, 'utf-8');
        
        debugger;
        */

        /*
        proxy_to_client_response.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8'
        });
        proxy_to_client_response.end('MOOO', 'utf-8');
        */

        // Choose http or https based on protocol
        const transport =
          ctx.client_to_proxy_request.parsed_request_url.protocol === 'https:'
            ? https
            : http;

        // debugger;
        const proxyReq = transport.request(
          {
            hostname: client_to_proxy_request.host_and_port.host,
            port: client_to_proxy_request.host_and_port.port,
            path:
              ctx.client_to_proxy_request.parsed_request_url.pathname +
              ctx.client_to_proxy_request.parsed_request_url.search,
            method: ctx.client_to_proxy_request.method,
            headers: ctx.client_to_proxy_request.headers
          },
          (proxyRes) => {
            // Write the headers and status from the destination to the client
            proxy_to_client_response.writeHead(
              proxyRes.statusCode || 500,
              proxyRes.headers
            );
            // Pipe the response from target back to the client
            proxyRes.pipe(proxy_to_client_response);
          }
        );

        proxyReq.on('error', (err) => {
          console.error('Proxy request error:', err);
          proxy_to_client_response.writeHead(502);
          proxy_to_client_response.end('Bad Gateway');
        });

        // Pipe the client request body to the destination
        client_to_proxy_request.pipe(proxyReq);
        return;
      }
    );

    const wss_mitm_server = new WebSocketServer({ server: https_mitm_server });
    wss_mitm_server.on(
      'connection',
      (websocket: WebSocket, request: IncomingMessage) => {
        debugger;
        /*
      websocket.upgradeReq = req;
      self._onWebSocketServerConnect.call(self, true, ws, req);
      */
      }
    );

    // start listening with the https server using localhost and the
    // first available port (port 0 selects any available)
    const listen_deferred: Deferred = new Deferred();
    let listening_port: number = 0;
    https_mitm_server.listen({ port: 0, host: '127.0.0.1' }, () => {
      listening_port = (https_mitm_server.address() as AddressInfo).port;
      listen_deferred.resolve(true);
    });
    await listen_deferred.promise;

    // define server set
    const mitm_server_set: mitm_server_set_t = {
      hostname: hostname,
      listening_port: listening_port,
      mitm_certs: mitm_certs,
      https_mitm_server: https_mitm_server,
      webscoket_mitm_server: wss_mitm_server
    };

    // add the proxy to the server map
    opsiproxy_ref.mitm_server_map.set(hostname, mitm_server_set);

    // return the created servers
    return mitm_server_set;
  }

  async handleHTTPsMITMDataStart(params: {
    ctx: OpsiProxyNetContext;
    client_socket: opsiproxy_socket_i;
    client_to_proxy_request: opsiproxy_http_incomming_message_i;
    head: Buffer;
    head_from_socket_data: Buffer;
  }) {
    const opsiproxy_ref = this;

    const head_data: Buffer = params.head.length
      ? params.head
      : params.head_from_socket_data;

    // always pause the socket on init
    params.client_socket.pause();

    // debugger;

    // check if this request is encrypted/ssl/tls/etc
    const is_encrypted = opsiproxy_ref.detectTLSFromRequestHead(head_data);
    if (is_encrypted) {
      params.ctx.stage.push(
        'http_server__client_to_proxy__encrypted_request_detected'
      );
      params.ctx.setHttpEventFlag('request_is_encrypted', true);
    }

    // set the request handle in the context
    params.ctx.client_to_proxy_request = params.client_to_proxy_request;

    if (!params.client_to_proxy_request.host_and_port) {
      await opsiproxy_ref.destroyContext(params.ctx);
      params.client_socket.destroy();
      return;
    }

    // IMPORTANT NOTE: For connect requests, the url will only be host:port, nothing else.

    /*
    // request URL must always be parsable
    if (!(await params.ctx.parseRequestURL(params.client_to_proxy_request))) {
      debugger;
      await opsiproxy_ref.destroyContext(params.ctx);
      params.client_socket.destroy();
      return;
    }
    */

    // create mitm server
    const mitm_server_set: mitm_server_set_t =
      await opsiproxy_ref.createHTTPsMITMServer(params.ctx);

    const net_connect_deferred: Deferred = new Deferred();
    const client_to_mitm_proxy_connection = net.connect(
      {
        port: mitm_server_set.listening_port,
        host: '127.0.0.1',
        allowHalfOpen: true
      },
      () => {
        // handle close events on both sockets
        client_to_mitm_proxy_connection.on('close', () => {
          params.client_socket.destroy();
        });
        params.client_socket.on('close', () => {
          client_to_mitm_proxy_connection.destroy();
        });

        // handle error events on both sockets
        client_to_mitm_proxy_connection.on('error', () => {
          params.client_socket.destroy();
        });
        params.client_socket.on('error', () => {
          client_to_mitm_proxy_connection.destroy();
        });

        // pipe the client socket through the mitm socket
        // and vice versa.  I think we can use an async generator here
        // to control packet traversals.
        params.client_socket.pipe(client_to_mitm_proxy_connection);
        client_to_mitm_proxy_connection.pipe(params.client_socket);

        // emit data to the client socket
        params.client_socket.emit('data', head_data);
        params.client_socket.resume();
        net_connect_deferred.resolve(true);
      }
    );

    await net_connect_deferred.promise;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Event Handlers %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  async setupNetProxyServerEventHandlers() {
    // set self reference
    const opsiproxy_ref = this;

    opsiproxy_ref.netServer.on('listening', async () => {
      // opsiproxy_ref.plugin_runner
      // debugger;
    });

    opsiproxy_ref.netServer.on('drop', async (data: net.DropArgument) => {
      debugger;
    });

    opsiproxy_ref.netServer.on('close', async () => {
      debugger;
    });

    opsiproxy_ref.netServer.on(
      'connection',
      async (socket: opsiproxy_socket_i) => {
        // Note: Socket is paused initially.  It must be resumed or the http server events
        //       will not trigger.

        // debugger;

        // create and register a new context
        const ctx = await opsiproxy_ref.createNetContext(socket);

        // run plugins
        const plugin_run_info: opsiproxy_plugin_runner_run_info_t =
          await opsiproxy_ref.plugin_runner.runPluginsBasedOnContext({
            ctx: ctx,
            opsiproxy_ref: opsiproxy_ref
          });

        // check for bad values
        if (plugin_run_info.plugin_route.proxy_server === 'unknown')
          throw new Error('plugin_runner_reports_unknown_server_context');
        if (plugin_run_info.plugin_route.proxy_server !== 'net')
          throw new Error('plugin_runner_reports_wrong_server_context');

        if (
          plugin_run_info.net_server_behavior ===
          'destroy_context_and_exit_stage'
        ) {
          await opsiproxy_ref.destroyContext(ctx);
          socket.destroy();
          return;
        }

        /*
        socket.on('data', (data: Buffer) => {
          debugger;
        });
        */

        if (plugin_run_info.net_server_behavior === 'stop_at_this_stage') {
        }

        // handle specific plugin behavior indicators
        // debugger;

        /*
        // if the socket is paused, unpause it to move to the next stage
        if (!socket.readableFlowing) {
          debugger;
          socket.resume();
        }
        */

        // emit connection event to the http server
        opsiproxy_ref.httpServer.emit('connection', socket);
      }
    );

    opsiproxy_ref.netServer.on('error', (err: Error) => {
      debugger;
    });

    return true;
  }

  // HTTP Proxy Server Event Handlers
  async setupHttpProxyServerEventHandlers() {
    // set self reference
    const opsiproxy_ref = this;

    // handle client->opsiproxy connections
    // self.httpServer!.on('connect', self._onHttpServerConnect.bind(self));

    // when the http server itself closes, not the request or connection
    opsiproxy_ref.httpServer.on('close', async () => {
      debugger;
    });

    opsiproxy_ref.httpServer.on(
      'dropRequest',
      async (request: http.IncomingMessage, socket: stream.Duplex) => {
        debugger;
      }
    );

    // This event is used for HTTPs.  When a proxy client tries to connect via https, this is where it goes,
    // and it asks to create a socket, not to make a request.
    opsiproxy_ref.httpServer.on(
      'connect',
      async (
        client_to_proxy_request: opsiproxy_http_incomming_message_i,
        client_socket: opsiproxy_socket_i,
        head: Buffer
      ) => {
        const ctx = (client_to_proxy_request.socket as opsiproxy_socket_i)
          .opsiproxy_net_ctx;

        // we should always have a context at this point
        if (!ctx) throw new Error('context_is_not_available_when_it_should_be');

        // parse the request host and port
        ctx.parseRequestHostAndPort(client_to_proxy_request);

        // often times, head is unset and we have to wait for data.  This is required
        // for us to be able to detect tls/ssl connections.
        if (!head || head.length === 0) {
          // we have to wait for data
          client_socket.once('data', async (data: Buffer) => {
            await opsiproxy_ref.handleHTTPsMITMDataStart({
              ctx: ctx,
              client_to_proxy_request: client_to_proxy_request,
              client_socket: client_socket,
              head: head,
              head_from_socket_data: data
            });
          });

          client_socket.write('HTTP/1.1 200 OK\r\n');
          /*
          if (
            self.keepAlive &&
            req.headers['proxy-connection'] === 'keep-alive'
          ) {
            socket.write('Proxy-Connection: keep-alive\r\n');
            socket.write('Connection: keep-alive\r\n');
          }
          */
          client_socket.write('\r\n');
          return;
        }

        await opsiproxy_ref.handleHTTPsMITMDataStart({
          ctx: ctx,
          client_socket: client_socket,
          client_to_proxy_request: client_to_proxy_request,
          head: head,
          head_from_socket_data: Buffer.from('')
        });

        // client_socket
        debugger;
        return;
        /*
        // gather existing context from map
        ctx.stage.push('http_server__client_to_proxy__request_recieved');
        ctx.setHttpEventFlag('request_context_is_valid', true);

        
        ctx.proxy_to_client_response = proxy_to_client_response;

        // request URL must always be parsable
        if (!(await ctx.parseRequestURL(client_to_proxy_request))) {
          ctx.client_to_proxy_requestTerminate('unparsable request url', 502);
          proxy_to_client_response.end();
          return;
        }

        let host: string = '';
        let port: number = -1;
        if (await ctx.parseRequestHostHeader(client_to_proxy_request)) {
          host = ctx.client_to_proxy_request.parsed_host_header.host;
          port = ctx.client_to_proxy_request.parsed_host_header.port;
        } else {
          host = ctx.client_to_proxy_request.parsed_request_url.hostname;
          port = parseInt(ctx.client_to_proxy_request.parsed_request_url.port);
        }

        // ensure the protocol is supported
        if (
          !['http:', 'https:', 'ws:', 'wss:'].includes(
            ctx.client_to_proxy_request.parsed_request_url.protocol
          )
        ) {
          ctx.client_to_proxy_requestTerminate('unsupported protocol', 502);
          proxy_to_client_response.end();
          return;
        }

        // pause the request
        ctx.client_to_proxy_request.pause();

        // debugger;

        const headers: http_headers_t = {};

        // don't forward proxy-headers
        for (const h in ctx.client_to_proxy_request.headers) {
          if (!/^proxy-/i.test(h)) {
            const header = ctx.client_to_proxy_request.headers[h];
            if (typeof header === 'string')
              if (typeof h === 'string') headers[h] = header;
          }
        }
        */

        /*
         * Detect TLS from first bytes of data
         * Inspired from https://gist.github.com/tg-x/835636
         * used heuristic:
         * - an incoming connection using SSLv3/TLSv1 records should start with 0x16
         * - an incoming connection using SSLv2 records should start with the record size
         *   and as the first record should not be very big we can expect 0x80 or 0x00 (the MSB is a flag)
         * - everything else is considered to be unencrypted
         */
        /*
        if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {
          // URL is in the form 'hostname:port'
          const hostname = req.url!.split(':', 2)[0];
          const sslServer = this.sslServers[hostname];
          if (sslServer) {
            return makeConnection(sslServer.port);
          }
          const wildcardHost = hostname.replace(/[^.]+\./, '*.');
          let sem = self.sslSemaphores[wildcardHost];
          if (!sem) {
            sem = self.sslSemaphores[wildcardHost] = semaphore(1);
          }
          sem.take(() => {
            if (self.sslServers[hostname]) {
              process.nextTick(sem.leave.bind(sem));
              return makeConnection(self.sslServers[hostname].port);
            }
            if (self.sslServers[wildcardHost]) {
              process.nextTick(sem.leave.bind(sem));
              self.sslServers[hostname] = {
                // @ts-ignore
                port: self.sslServers[wildcardHost].port
              };
              return makeConnection(self.sslServers[hostname].port);
            }
            getHttpsServer(hostname, (err, port) => {
              process.nextTick(sem.leave.bind(sem));
              if (err) {
                console.error('Error getting HTTPs server');
                console.error(err);
                return self._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
              }
              return makeConnection(port);
            });
            delete self.sslSemaphores[wildcardHost];
          });
        } else {
          return makeConnection(this.httpPort);
        }
        */

        // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        // %%% Create Tunnel %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

        const [host, port] = client_to_proxy_request.url!.split(':');
        const serverSocket = net.connect(Number(port), host, async () => {
          client_socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

          // this is where we create a https server

          // Pipe the initial buffered data, if any
          if (head && head.length > 0) {
            serverSocket.write(head);
          }

          // Tunnel data between client and target server
          client_socket.pipe(serverSocket);
          serverSocket.pipe(client_socket);
        });

        serverSocket.on('error', (err) => {
          console.error(`Error connecting to ${host}:${port}`, err.message);
          client_socket.end();
        });
      }
    );

    opsiproxy_ref.httpServer.on('connection', (socket: opsiproxy_socket_i) => {
      const ctx = socket.opsiproxy_net_ctx;

      /*
        // set socket uuid on connection
        socket.uuid = randomGuid();
        // create new context and immediately pause the request
        const ctx = new OpsiproxyRequestContext();
        ctx.stage.push('client_to_proxy__connection');
        ctx.opsiproxy_ref = opsiproxy_ref;
        ctx.socket = socket;
        ctx.uuid = socket.uuid;
        ctx.setHttpEventFlag('connection', true);

        // add context to the context map
        opsiproxy_ref.context_map.set(ctx.uuid, ctx);
        ctx.setHttpEventFlag('context_added_to_map', true);

        // create a deferral so that other events know to pause here
        socket.deferral = ctx.deferred_map.deferred();

        for (
          let plugin_idx = 0;
          plugin_idx < opsiproxy_ref.plugins.length;
          plugin_idx++
        ) {
          const plugin = opsiproxy_ref.plugins[plugin_idx];
          if (plugin.clientToProxy_onConnection) {
            const plugin_result = await plugin.clientToProxy_onConnection({
              ctx: ctx
            });

            // don't mark noops
            if (!plugin_result) continue;
            if (plugin_result.behavior === 'noop') continue;

            // set plugin event flag in context
            ctx.setPluginEventFlag(
              plugin,
              'connection',
              plugin_result.behavior
            );

            if (plugin_result.behavior === 'go_next_stage') break;
            if (plugin_result.behavior === 'handled') return;
            if (plugin_result.behavior === 'continue') continue;
            if (plugin_result.behavior === 'end') {
              socket.destroy();
              socket.deferral.resolve(false);
              return;
            }
          }
        }

        // resume the socket after paused
        // socket.resume();
        // socket.deferral.resolve(true);
        // debugger;
        */
    });

    // handle client->opsiproxy requests
    // self.httpServer!.on('request', self._onHttpServerRequest.bind(self, false));
    opsiproxy_ref.httpServer.on(
      'request',
      async (
        client_to_proxy_request: opsiproxy_http_incomming_message_i,
        proxy_to_client_response: opsiproxy_http_proxy_to_client_response_message_i
      ) => {
        // debugger;
        // gather context
        const ctx = (client_to_proxy_request.socket as opsiproxy_socket_i)
          .opsiproxy_net_ctx;
        if (!ctx) throw new Error('request_with_no_context_is_unreasonable');

        // proxy_to_client_response.end();

        // gather existing context from map
        ctx.stage.push('http_server__client_to_proxy__request_recieved');
        ctx.setHttpEventFlag('request_context_is_valid', true);

        ctx.client_to_proxy_request = client_to_proxy_request;
        ctx.proxy_to_client_response = proxy_to_client_response;

        // request URL must always be parsable
        if (!(await ctx.parseRequestURL(client_to_proxy_request))) {
          ctx.client_to_proxy_requestTerminate('unparsable request url', 502);
          proxy_to_client_response.end();
          return;
        }

        let host: string = '';
        let port: number = -1;
        if (await ctx.parseRequestHostHeader(client_to_proxy_request)) {
          host = ctx.client_to_proxy_request.parsed_host_header.host;
          port = ctx.client_to_proxy_request.parsed_host_header.port;
        } else {
          host = ctx.client_to_proxy_request.parsed_request_url.hostname;
          port = parseInt(ctx.client_to_proxy_request.parsed_request_url.port);
        }

        // ensure the protocol is supported
        if (
          !['http:', 'https:', 'ws:', 'wss:'].includes(
            ctx.client_to_proxy_request.parsed_request_url.protocol
          )
        ) {
          ctx.client_to_proxy_requestTerminate('unsupported protocol', 502);
          proxy_to_client_response.end();
          return;
        }

        // pause the request
        ctx.client_to_proxy_request.pause();

        // debugger;

        const headers: http_headers_t = {};

        // don't forward proxy-headers
        for (const h in ctx.client_to_proxy_request.headers) {
          if (!/^proxy-/i.test(h)) {
            const header = ctx.client_to_proxy_request.headers[h];
            if (typeof header === 'string')
              if (typeof h === 'string') headers[h] = header;
          }
        }

        // Choose http or https based on protocol
        const transport =
          ctx.client_to_proxy_request.parsed_request_url.protocol === 'https:'
            ? https
            : http;

        // debugger;
        const proxyReq = transport.request(
          {
            hostname: host,
            port: port,
            path:
              ctx.client_to_proxy_request.parsed_request_url.pathname +
              ctx.client_to_proxy_request.parsed_request_url.search,
            method: ctx.client_to_proxy_request.method,
            headers: ctx.client_to_proxy_request.headers
          },
          (proxyRes) => {
            // Write the headers and status from the destination to the client
            proxy_to_client_response.writeHead(
              proxyRes.statusCode || 500,
              proxyRes.headers
            );
            // Pipe the response from target back to the client
            proxyRes.pipe(proxy_to_client_response);
          }
        );

        proxyReq.on('error', (err) => {
          console.error('Proxy request error:', err);
          proxy_to_client_response.writeHead(502);
          proxy_to_client_response.end('Bad Gateway');
        });

        // Pipe the client request body to the destination
        client_to_proxy_request.pipe(proxyReq);

        /*

        function makeProxyToServerRequest() {
          const proto = ctx.isSSL ? https : http;
          ctx.proxy_to_server_request = proto.request(
            ctx.proxy_to_server_request_options!,
            proxy_to_server_requestComplete
          );
          ctx.proxy_to_server_request.on(
            'error',
            self._onError.bind(self, 'PROXY_TO_SERVER_REQUEST_ERROR', ctx)
          );
          ctx.requestFilters.push(new ProxyFinalRequestFilter(self, ctx));
          let prevRequestPipeElem = ctx.client_to_proxy_request;
          ctx.requestFilters.forEach((filter) => {
            filter.on(
              'error',
              self._onError.bind(self, 'REQUEST_FILTER_ERROR', ctx)
            );
            prevRequestPipeElem = prevRequestPipeElem.pipe(filter);
          });
          ctx.client_to_proxy_request.resume();
        }

        */

        /*
        if (this.options.forceChunkedRequest) {
          delete headers['content-length'];
        }

        ctx.proxy_to_server_request_options = {
          method: ctx.client_to_proxy_request.method!,
          path: ctx.client_to_proxy_request.url!,
          host: hostPort.host,
          port: hostPort.port,
          headers,
          agent: ctx.isSSL ? self.httpsAgent : self.httpAgent
        };
        return self._onRequest(ctx, (err) => {
          if (err) {
            return self._onError('ON_REQUEST_ERROR', ctx, err);
          }
          return self._onRequestHeaders(ctx, (err: Error | undefined | null) => {
            if (err) {
              return self._onError('ON_REQUESTHEADERS_ERROR', ctx, err);
            }
            return makeProxyToServerRequest();
          });
        });
        */

        /*
        const hostPort = {
          host: '',
          port: 0
        };



        if (this.options.forceChunkedRequest) {
          delete headers['content-length'];
        }

        ctx.proxy_to_server_request_options = {
          method: ctx.client_to_proxy_request.method!,
          path: ctx.client_to_proxy_request.url!,
          host: hostPort.host,
          port: hostPort.port,
          headers: headers,
          agent: ctx.isSSL ? opsiproxy_ref.httpsAgent : opsiproxy_ref.httpAgent
        };

        // iterate through request plugins
        if (opsiproxy_ref?.options?.plugins) {
          for (let idx = 0; idx < opsiproxy_ref.options.plugins.length; idx++) {
            const plugin = opsiproxy_ref.options.plugins[idx];
            if (!plugin.onRequest) continue;
          }
        }
          */

        // debugger;
      }
    );

    /*
    if (self.forceSNI) {
      // start the single HTTPS server now
      self._createHttpsServer({}, (port, httpsServer, wssServer) => {
        console.debug(`https server started on ${port}`);
        self.httpsServer = httpsServer;
        self.wssServer = wssServer;
        self.httpsPort = port;
        self.httpServer!.listen(listenOptions, () => {
          self.httpPort = (self.httpServer!.address() as AddressInfo).port;
        });
      });
    } else {
     */
  }

  async setupHttpProxyWebsocketServerEventHandlers() {
    // set self reference
    const opsiproxy_ref = this;

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% WebSocket Server %%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    opsiproxy_ref.wsServer = new WebSocketServer({
      server: opsiproxy_ref.httpServer
    });

    /*
    self.wsServer.on(
      'error',
      self._onError.bind(self, 'HTTP_SERVER_ERROR', null)
    );
    */
    opsiproxy_ref.wsServer.on('error', (error: Error) => {
      debugger;
    });

    /*
    self.wsServer.on(
      'connection',
      (ws: opsiproxy_websocket_i, req: IncomingMessage) => {
        ws.upgradeReq = req;
        self._onWebSocketServerConnect.call(self, false, ws, req);
      }
    );
    */
    opsiproxy_ref.wsServer.on(
      'connection',
      (ws: opsiproxy_websocket_i, req: IncomingMessage) => {
        debugger;
      }
    );
  }

  async close() {
    // set self reference
    const opsiproxy_ref = this;

    // close/remove http server
    opsiproxy_ref.httpServer!.close();

    // close/remove https server
    if (opsiproxy_ref.httpsServer) {
      opsiproxy_ref.httpsServer.close();
      opsiproxy_ref.sslServers = {};
    }

    // close/remove sslServers
    if (this.sslServers) {
      for (const srvName of Object.keys(opsiproxy_ref.sslServers)) {
        const server = opsiproxy_ref.sslServers[srvName].server;
        if (server) {
          server.close();
        }
        delete opsiproxy_ref.sslServers[srvName];
      }
    }
    return true;
  }
}

export {
  OpsiHTTPProxy,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_t,
  opsiproxy_plugin_event_cb_t,
  opsiproxy_plugin_method_ret_t,
  opsiproxy_options_t,
  opsiproxy_socket_i
};
