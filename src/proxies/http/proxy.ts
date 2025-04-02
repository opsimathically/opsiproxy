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
  OpsiproxyRequestContext,
  opsiproxy_http_incomming_message_i
} from '@src/proxies/http/contexts/OpsiproxyRequestContext.class';

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
type plugin_method_ret_t = {
  /**
   * end:
   * Will call context end, destroying the entire context, stopping any further
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
  behavior: 'end' | 'continue' | 'handled' | 'noop' | 'go_next_stage';
};

type opsiproxy_plugin_t = {
  info: opsiproxy_plugin_info_t;

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Client To Proxy Events %%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  clientToProxy_onConnection?(params: {
    ctx: OpsiproxyRequestContext;
  }): Promise<plugin_method_ret_t | undefined>;

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Proxy To Server Events %%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  onError?(): Promise<any>;
  onConnect?(): Promise<any>;
  onRequestHeaders?(): Promise<any>;
  onRequest?(params: {
    opsiproxy_ref: OpsiHTTPProxy;
    request_context: OpsiproxyRequestContext;
  }): Promise<any>;
  onWebSocketConnection?(): Promise<any>;
  onWebSocketSend?(): Promise<any>;
  onWebSocketMessage?(): Promise<any>;
  onWebSocketFrame?(): Promise<any>;
  onWebSocketClose?(): Promise<any>;
  onWebSocketError?(): Promise<any>;
  onRequestData?(): Promise<any>;
  onRequestEnd?(): Promise<any>;
  onResponse?(): Promise<any>;
  onResponseHeaders?(): Promise<any>;
  onResponseData?(): Promise<any>;
  onResponseEnd?(): Promise<any>;
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
}

type opsiproxy_options_t = {
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
  plugins: opsiproxy_plugin_t[];
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
  ca!: ca;
  connectRequests: Record<string, http.IncomingMessage> = {};
  forceSNI!: boolean;
  httpAgent!: http.Agent;
  httpHost?: string;
  httpPort!: number;
  httpServer: HTTPServer | undefined = http.createServer();
  httpsAgent!: https.Agent;
  httpsPort?: number;
  httpsServer: Server | undefined;
  keepAlive!: boolean;

  // opsiproxy plugins
  plugins: opsiproxy_plugin_t[] = [];

  // socket manager
  context_map: Map<string, OpsiproxyRequestContext> = new Map<
    string,
    OpsiproxyRequestContext
  >();

  /*
  onConnectHandlers: HandlerType<IProxy['onConnect']>;
  onErrorHandlers: HandlerType<IProxy['onError']>;
  onRequestDataHandlers: HandlerType<IProxy['onRequestData']>;
  onRequestEndHandlers: HandlerType<IProxy['onRequestEnd']>;
  onRequestHandlers: HandlerType<IProxy['onRequest']>;
  onRequestHeadersHandlers: HandlerType<IProxy['onRequestHeaders']>;
  onResponseDataHandlers: HandlerType<IProxy['onResponseData']>;
  onResponseEndHandlers: HandlerType<IProxy['onResponseEnd']>;
  onResponseHandlers: HandlerType<IProxy['onResponse']>;
  onResponseHeadersHandlers: HandlerType<IProxy['onResponseHeaders']>;
  onWebSocketCloseHandlers: HandlerType<IProxy['onWebSocketClose']>;
  onWebSocketConnectionHandlers: HandlerType<IProxy['onWebSocketConnection']>;
  onWebSocketErrorHandlers: HandlerType<IProxy['onWebSocketError']>;
  onWebSocketFrameHandlers: HandlerType<IProxy['onWebSocketFrame']>;
  */
  options!: opsiproxy_options_t;
  responseContentPotentiallyModified: boolean;
  sslCaDir!: string;
  sslSemaphores: Record<string, semaphore.Semaphore> = {};
  sslServers: Record<string, IProxySSLServer> = {};
  timeout!: number;
  wsServer: WebSocketServer | undefined;
  wssServer: WebSocketServer | undefined;
  static wildcard = wildcard;
  static gunzip = gunzip;

  constructor(params: opsiproxy_options_t) {
    this.options = params;
    this.plugins = params.plugins;
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
    this.responseContentPotentiallyModified = false;
  }

  // check if something is a writable directory
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

  async listen() {
    // set self reference
    const opsiproxy_ref = this;

    // set options
    const options = opsiproxy_ref.options;
    opsiproxy_ref.httpPort = options.httpPort;

    opsiproxy_ref.httpHost = options.host;
    opsiproxy_ref.timeout = options.timeout;
    opsiproxy_ref.keepAlive = options.keepAlive;

    opsiproxy_ref.httpAgent =
      typeof options.httpAgent !== 'undefined'
        ? options.httpAgent
        : new http.Agent({ keepAlive: this.keepAlive });

    opsiproxy_ref.httpsAgent = options.httpsAgent;

    opsiproxy_ref.forceSNI = options.forceSNI;

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Certificate Authority %%%%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // always ensure the ca directory exists
    opsiproxy_ref.sslCaDir = options.sslCaDir;
    if (!(await opsiproxy_ref.isWritableDirectory(opsiproxy_ref.sslCaDir))) {
      throw new Error('opsiproxy_ssl_ca_dir_is_invalid');
    }

    // attempt to create the certificate authority instance
    const certificate_authority: ca = await new Promise(function (
      resolve,
      reject
    ) {
      ca.create(
        opsiproxy_ref.sslCaDir,
        (err: Error | null | undefined, ca: ca) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(ca);
        }
      );
    });

    opsiproxy_ref.ca = certificate_authority;
    opsiproxy_ref.sslServers = {};
    opsiproxy_ref.sslSemaphores = {};
    opsiproxy_ref.connectRequests = {};

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% HTTP Server/Event Handlers %%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    opsiproxy_ref.httpServer = http.createServer();
    opsiproxy_ref.httpServer.timeout = opsiproxy_ref.timeout;

    // handle client->opsiproxy connections
    // self.httpServer!.on('connect', self._onHttpServerConnect.bind(self));

    // when the http server itself closes, not the request or connection
    opsiproxy_ref.httpServer.on('close', async () => {});

    opsiproxy_ref.httpServer.on(
      'dropRequest',
      async (request: http.IncomingMessage, socket: stream.Duplex) => {}
    );

    // NOTE: For people reading this code, this is the CONNECT method, not the socket connecting.
    opsiproxy_ref.httpServer.on(
      'connect',
      async (req: IncomingMessage, socket: stream.Duplex, head: Buffer) => {
        debugger;
      }
    );

    opsiproxy_ref.httpServer.on(
      'connection',
      async (socket: opsiproxy_socket_i) => {
        // set socket uuid on connection
        socket.uuid = randomGuid();
        // create new context and immediately pause the request
        const ctx = new OpsiproxyRequestContext();
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

            if (plugin_result.behavior === 'handled') break;
            if (plugin_result.behavior === 'continue') continue;
            if (plugin_result.behavior === 'end') {
              socket.deferral.resolve(false);
              return;
            }
          }
        }

        socket.deferral.resolve(true);
        debugger;
      }
    );

    // handle client->opsiproxy requests
    // self.httpServer!.on('request', self._onHttpServerRequest.bind(self, false));
    opsiproxy_ref.httpServer.on(
      'request',
      async (
        clientToProxyRequest: opsiproxy_http_incomming_message_i,
        proxyToClientResponse: ServerResponse<IncomingMessage> & {
          req: IncomingMessage;
        }
      ) => {
        const opsiproxy_socket: opsiproxy_socket_i =
          clientToProxyRequest.socket as opsiproxy_socket_i;

        if (!opsiproxy_socket.deferral?.promise)
          throw new Error('socket_did_not_contain_a_deferral');

        // we need to wait for the socket deferral to resolve, this is how we
        // force synchronization between our async plugin callbacks.
        const deferral_result = await opsiproxy_socket.deferral.promise;
        if (!deferral_result) {
          return;
        }

        debugger;
        const request_socket_uuid = (
          clientToProxyRequest.socket as opsiproxy_socket_i
        ).uuid;
        if (!request_socket_uuid) {
          proxyToClientResponse.end();
          return;
        }

        // gather existing context from map
        const ctx = opsiproxy_ref.context_map.get(request_socket_uuid);
        if (!ctx) {
          proxyToClientResponse.end();
          return;
        }

        ctx.setHttpEventFlag('request_context_is_valid', true);

        debugger;
        /*
        ctx.clientToProxyRequest = clientToProxyRequest;
        ctx.clientToProxyRequest.pause();
        ctx.isSSL = false;
        ctx.proxyToClientResponse = proxyToClientResponse;
        ctx.responseContentPotentiallyModified = false;

        // attempt to parse url and host header
        const request_url_parsed_ok =
          await ctx.parseRequestURL(clientToProxyRequest);
        const host_header_parsed_ok =
          await ctx.parseRequestHostHeader(clientToProxyRequest);
        */
        debugger;
        /*
        const hostPort = {
          host: '',
          port: 0
        };


        // use host header by default, fallback to request
        if (host_header_parsed_ok) {
          hostPort.host = ctx.clientToProxyRequest.parsed_host_header.host;
          hostPort.port = ctx.clientToProxyRequest.parsed_host_header.port;
        } else if (request_url_parsed_ok) {
        } else {
        }

        const hostPort = OpsiHTTPProxy.parseHostAndPort(
          ctx.clientToProxyRequest,
          ctx.isSSL ? 443 : 80
        );

        debugger;
        // ensure hostPort was parsed ok
        if (!hostPort) {
          ctx.clientToProxyRequest.resume();
          ctx.proxyToClientResponse.writeHead(400, {
            'Content-Type': 'text/html; charset=utf-8'
          });
          ctx.proxyToClientResponse.end(
            'Bad request: Host missing...',
            'utf-8'
          );
          return;
        }

        const headers: http_headers_t = {};
        for (const h in ctx.clientToProxyRequest.headers) {
          // don't forward proxy-headers
          if (!/^proxy-/i.test(h)) {
            const header = ctx.clientToProxyRequest.headers[h];
            if (typeof header === 'string')
              if (typeof h === 'string') headers[h] = header;
          }
        }

        if (this.options.forceChunkedRequest) {
          delete headers['content-length'];
        }

        ctx.proxyToServerRequestOptions = {
          method: ctx.clientToProxyRequest.method!,
          path: ctx.clientToProxyRequest.url!,
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
        debugger;
      }
    );

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

    const listenOptions = {
      host: opsiproxy_ref.httpHost,
      port: opsiproxy_ref.httpPort
    };

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

    await new Promise(function (resolve, reject) {
      if (!opsiproxy_ref.httpServer) {
        reject('opsiproxy_http_server_not_present');
        return;
      }
      opsiproxy_ref.httpServer.listen(listenOptions, () => {
        opsiproxy_ref.httpPort = (
          opsiproxy_ref.httpServer!.address() as AddressInfo
        ).port;
        resolve(true);
      });
    });
    /*
    }
    */

    return true;
  }

  async close() {
    // set self reference
    const opsiproxy_ref = this;

    // close/remove http server
    opsiproxy_ref.httpServer!.close();
    delete opsiproxy_ref.httpServer;

    // close/remove https server
    if (opsiproxy_ref.httpsServer) {
      opsiproxy_ref.httpsServer.close();

      delete opsiproxy_ref.httpsServer;
      delete opsiproxy_ref.wssServer;

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

  /*
  _createHttpsServer(
    options: ServerOptions & { hosts?: string[] },
    callback: ICreateServerCallback
  ) {
    const httpsServer = https.createServer({
      ...options
    } as ServerOptions);

    httpsServer.timeout = this.timeout;

    httpsServer.on(
      'error',
      this._onError.bind(this, 'HTTPS_SERVER_ERROR', null)
    );

    httpsServer.on(
      'clientError',
      this._onError.bind(this, 'HTTPS_CLIENT_ERROR', null)
    );

    httpsServer.on('connect', this._onHttpServerConnect.bind(this));
    httpsServer.on('request', this._onHttpServerRequest.bind(this, true));
    const self = this;
    const wssServer = new WebSocketServer({ server: httpsServer });
    wssServer.on('connection', (ws: opsiproxy_websocket_i, req) => {
      ws.upgradeReq = req;
      self._onWebSocketServerConnect.call(self, true, ws, req);
    });

    // Using listenOptions to bind the server to a particular IP if requested via options.host
    // port 0 to get the first available port
    const listenOptions = {
      port: 0,
      host: '0.0.0.0'
    };
    if (this.httpsPort && !options.hosts) {
      listenOptions.port = this.httpsPort;
    }
    if (this.httpHost) {
      listenOptions.host = this.httpHost;
    }

    httpsServer.listen(listenOptions, () => {
      if (callback) {
        callback(
          (httpsServer.address() as AddressInfo).port,
          httpsServer,
          wssServer
        );
      }
    });
  }
  */

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Handler Definitions %%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  /*
  onError(fn: OnErrorParams) {
    this.onErrorHandlers.push(fn);
    return this;
  }

  onConnect(fn: OnConnectParams) {
    this.onConnectHandlers.push(fn);
    return this;
  }

  onRequestHeaders(fn: OnRequestParams) {
    this.onRequestHeadersHandlers.push(fn);
    return this;
  }

  onRequest(fn: OnRequestParams) {
    this.onRequestHandlers.push(fn);
    return this;
  }

  onWebSocketConnection(fn: OnWebsocketRequestParams) {
    this.onWebSocketConnectionHandlers.push(fn);
    return this;
  }

  onWebSocketSend(fn: OnWebSocketSendParams) {
    this.onWebSocketFrameHandlers.push(
      function (
        ctx: any,
        type: string,
        fromServer: any,
        data: any,
        flags: any,
        callback: (arg0: null, arg1: any, arg2: any) => void
      ) {
        if (!fromServer && type === 'message') {
          return this(ctx, data, flags, callback);
        } else {
          callback(null, data, flags);
        }
      }.bind(fn)
    );
    return this;
  }

  onWebSocketMessage(fn: OnWebSocketMessageParams) {
    this.onWebSocketFrameHandlers.push(
      function (
        ctx: any,
        type: string,
        fromServer: any,
        data: any,
        flags: any,
        callback: (arg0: null, arg1: any, arg2: any) => void
      ) {
        if (fromServer && type === 'message') {
          return this(ctx, data, flags, callback);
        } else {
          callback(null, data, flags);
        }
      }.bind(fn)
    );
    return this;
  }

  onWebSocketFrame(fn: OnWebSocketFrameParams) {
    this.onWebSocketFrameHandlers.push(fn);
    return this;
  }

  onWebSocketClose(fn: OnWebSocketCloseParams) {
    this.onWebSocketCloseHandlers.push(fn);
    return this;
  }

  onWebSocketError(fn: OnWebSocketErrorParams) {
    this.onWebSocketErrorHandlers.push(fn);
    return this;
  }

  onRequestData(fn: OnRequestDataParams) {
    this.onRequestDataHandlers.push(fn);
    return this;
  }

  onRequestEnd(fn: OnRequestParams) {
    this.onRequestEndHandlers.push(fn);
    return this;
  }

  onResponse(fn: OnRequestParams) {
    this.onResponseHandlers.push(fn);
    return this;
  }

  onResponseHeaders(fn: OnRequestParams) {
    this.onResponseHeadersHandlers.push(fn);
    return this;
  }

  onResponseData(fn: OnRequestDataParams) {
    this.onResponseDataHandlers.push(fn);
    this.responseContentPotentiallyModified = true;
    return this;
  }

  onResponseEnd(fn: OnRequestParams) {
    this.onResponseEndHandlers.push(fn);
    return this;
  }
  */

  /*
  // Since node 0.9.9, ECONNRESET on sockets are no longer hidden
  _onSocketError(socketDescription: string, err: NodeJS.ErrnoException) {
    if (err.errno === -54 || err.code === 'ECONNRESET') {
      console.debug(`Got ECONNRESET on ${socketDescription}, ignoring.`);
    } else {
      this._onError(`${socketDescription}_ERROR`, null, err);
    }
  }
  */

  async _onHttpServerConnect(
    req: http.IncomingMessage,
    socket: stream.Duplex,
    head: Buffer
  ) {
    /*
    const self = this;

    socket.on(
      'error',
      self._onSocketError.bind(self, 'CLIENT_TO_PROXY_SOCKET')
    );

    const ia = new IterAsync<opsiproxy_plugin_t, any>({
      concurrency: 10,
      extra: {},
      gen: async function* () {
        for (let idx = 0; idx < self.plugins.length; idx++) {
          yield self.plugins[idx];
        }
      },
      processor: async function (
        this: IterAsync<opsiproxy_plugin_t, any>,
        item: opsiproxy_plugin_t
      ) {}
    });

    await ia.run();
    

    if (!head || head.length === 0) {
      socket.once(
        'data',
        self._onHttpServerConnectData.bind(self, req, socket)
      );
      socket.write('HTTP/1.1 200 OK\r\n');
      if (self.keepAlive && req.headers['proxy-connection'] === 'keep-alive') {
        socket.write('Proxy-Connection: keep-alive\r\n');
        socket.write('Connection: keep-alive\r\n');
      }
      return socket.write('\r\n');
    } else {
      self._onHttpServerConnectData(req, socket, head);
    }
    */
    /*
    // you can forward HTTPS request directly by adding custom CONNECT method handler
    return async.forEach(
      self.onConnectHandlers,
      (fn, callback) => {
        fn.call(self, req, socket, head, callback);
      },
      (err) => {
        if (err) {
          return self._onError('ON_CONNECT_ERROR', null, err);
        }
        // we need first byte of data to detect if request is SSL encrypted

        if (!head || head.length === 0) {
          socket.once(
            'data',
            self._onHttpServerConnectData.bind(self, req, socket)
          );
          socket.write('HTTP/1.1 200 OK\r\n');
          if (
            self.keepAlive &&
            req.headers['proxy-connection'] === 'keep-alive'
          ) {
            socket.write('Proxy-Connection: keep-alive\r\n');
            socket.write('Connection: keep-alive\r\n');
          }
          return socket.write('\r\n');
        } else {
          self._onHttpServerConnectData(req, socket, head);
        }
      }
    );
    */
  }

  /*
  async makeConnection(
    req: http.IncomingMessage,
    socket: stream.Duplex,
    head: Buffer,
    port: number
  ) {
    const self = this;

    // open a TCP connection to the remote host
    const conn = net.connect(
      {
        port,
        host: '0.0.0.0',
        allowHalfOpen: true
      },

      () => {
        // create a tunnel between the two hosts
        const connectKey = `${conn.localPort}:${conn.remotePort}`;
        self.connectRequests[connectKey] = req;
        const cleanupFunction = () => {
          delete self.connectRequests[connectKey];
        };
        conn.on('close', () => {
          cleanupFunction();
          socket.destroy();
        });
        socket.on('close', () => {
          conn.destroy();
        });
        conn.on('error', (err) => {
          console.error('Connection error:');
          console.error(err);
          conn.destroy();
        });
        socket.on('error', (err) => {
          console.error('Socket error:');
          console.error(err);
        });
        socket.pipe(conn);
        conn.pipe(socket);
        socket.emit('data', head);
        return socket.resume();
      }
    );
    conn.on('error', self._onSocketError.bind(self, 'PROXY_TO_PROXY_SOCKET'));
  }
  */

  /*
  async getHttpsServer(hostname: string, callback: ErrorCallback) {
    const self = this;

    const files = {
      keyFile: `${self.sslCaDir}/keys/${hostname}.key`,
      certFile: `${self.sslCaDir}/certs/${hostname}.pem`,
      hosts: [hostname]
    };

    let keyfile_exists = false;
    try {
      await access(files.keyFile, constants.F_OK);
      keyfile_exists = true;
    } catch (err) {}

    let certfile_exists = false;
    try {
      await access(files.certFile, constants.F_OK);
      certfile_exists = true;
    } catch (err) {}

    if (keyfile_exists && certfile_exists) {
      let keyfile_content = fs_promises.readFile(files.keyFile);
      let certfile_content = fs_promises.readFile(files.certFile);
      const cert_data = {
        key: keyfile_content,
        cert: certfile_content,
        hosts: files.hosts
      };
    } else {
      const ctx: ICertficateContext = {
        hostname: hostname,
        files: files,
        data: {
          keyFileExists: keyfile_exists,
          certFileExists: certfile_exists
        }
      };

      const hosts = files.hosts || [ctx.hostname];

      const generated_certs = await new Promise(function (resolve, reject) {
        self.ca.generateServerCertificateKeys(
          hosts,
          (certPEM: any, privateKeyPEM: any) => {
            resolve({
              key: certPEM,
              cert: privateKeyPEM,
              hosts: hosts
            });
          }
        );
      });
    }

    let hosts;
    if (
      results.httpsOptions &&
      results.httpsOptions.hosts &&
      results.httpsOptions.hosts.length
    ) {
      hosts = results.httpsOptions.hosts;
      if (!hosts.includes(hostname)) {
        hosts.push(hostname);
      }
    } else {
      hosts = [hostname];
    }

    delete results.httpsOptions.hosts;
    if (self.forceSNI && !hostname.match(/^[\d.]+$/)) {
      console.debug(`creating SNI context for ${hostname}`);
      hosts.forEach((host: string) => {
        self.httpsServer!.addContext(host, results.httpsOptions);
        self.sslServers[host] = { port: Number(self.httpsPort) };
      });
      return callback(null, self.httpsPort);
    } else {
      console.debug(`starting server for ${hostname}`);
      results.httpsOptions.hosts = hosts;
      try {
        self._createHttpsServer(
          results.httpsOptions,
          (port, httpsServer, wssServer) => {
            console.debug(`https server started for ${hostname} on ${port}`);
            const sslServer = {
              server: httpsServer,
              wsServer: wssServer,
              port
            };
            hosts.forEach((host: string | number) => {
              self.sslServers[host] = sslServer;
            });
            return callback(null, port);
          }
        );
      } catch (err: any) {
        return callback(err);
      }
    }

    // results: { httpsOptions: SecureContextOptions }
  }
  */

  /*
  async _onHttpServerConnectData(
    req: http.IncomingMessage,
    socket: stream.Duplex,
    head: Buffer
  ) {
    const self = this;

    socket.pause();

    
    // * Detect TLS from first bytes of data
    // * Inspired from https://gist.github.com/tg-x/835636
    // * used heuristic:
    // * - an incoming connection using SSLv3/TLSv1 records should start with 0x16
    // * - an incoming connection using SSLv2 records should start with the record size
    // *   and as the first record should not be very big we can expect 0x80 or 0x00 (the MSB is a flag)
    // * - everything else is considered to be unencrypted
     
    if (head[0] == 0x16 || head[0] == 0x80 || head[0] == 0x00) {
      // URL is in the form 'hostname:port'
      const hostname = req.url!.split(':', 2)[0];

      const sslServer = this.sslServers[hostname];

      if (sslServer) {
        return self.makeConnection(req, socket, head, sslServer.port);
      }

      const wildcardHost = hostname.replace(/[^.]+\./, '*.');

      let sem = self.sslSemaphores[wildcardHost];
      if (!sem) {
        sem = self.sslSemaphores[wildcardHost] = semaphore(1);
      }

      sem.take(() => {
        if (self.sslServers[hostname]) {
          process.nextTick(sem.leave.bind(sem));
          return self.makeConnection(
            req,
            socket,
            head,
            self.sslServers[hostname].port
          );
        }

        if (self.sslServers[wildcardHost]) {
          process.nextTick(sem.leave.bind(sem));
          self.sslServers[hostname] = {
            // @ts-ignore
            port: self.sslServers[wildcardHost].port
          };
          return self.makeConnection(
            req,
            socket,
            head,
            self.sslServers[hostname].port
          );
        }

        getHttpsServer(hostname, (err, port) => {
          process.nextTick(sem.leave.bind(sem));
          if (err) {
            console.error('Error getting HTTPs server');
            console.error(err);
            return self._onError('OPEN_HTTPS_SERVER_ERROR', null, err);
          }
          return self.makeConnection(req, socket, head, port);
        });

        delete self.sslSemaphores[wildcardHost];
      });
    } else {
      return self.makeConnection(req, socket, head, this.httpPort);
    }
  }
  */

  /*
  onCertificateRequired(
    hostname: string,
    callback: OnCertificateRequiredCallback
  ) {
    const self = this;
    return callback(null, {
      keyFile: `${self.sslCaDir}/keys/${hostname}.key`,
      certFile: `${self.sslCaDir}/certs/${hostname}.pem`,
      hosts: [hostname]
    });
  }
  */

  /*
  onCertificateMissing(
    ctx: ICertficateContext,
    files: ICertDetails,
    callback: ErrorCallback
  ) {
    const hosts = files.hosts || [ctx.hostname];
    this.ca.generateServerCertificateKeys(
      hosts,
      (certPEM: any, privateKeyPEM: any) => {
        callback(null, {
          certFileData: certPEM,
          keyFileData: privateKeyPEM,
          hosts
        });
      }
    );
  }
  */

  /*
  _onError(kind: string, ctx: IContext | null, err: Error) {
    console.error(kind);
    console.error(err);

    this.onErrorHandlers.forEach((handler) => handler(ctx, err, kind));
    if (ctx) {
      ctx.onErrorHandlers.forEach((handler) => handler(ctx, err, kind));

      if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.headersSent) {
        ctx.proxyToClientResponse.writeHead(504, 'Proxy Error');
      }
      if (ctx.proxyToClientResponse && !ctx.proxyToClientResponse.finished) {
        ctx.proxyToClientResponse.end(`${kind}: ${err}`, 'utf8');
      }
    }
  }
  */

  /*
  _onWebSocketServerConnect(
    isSSL: boolean,
    ws: WebSocketType,
    upgradeReq: IncomingMessage
  ) {
    const self = this;
    // @ts-ignore
    const socket = ws._socket;
    const ctx: IWebSocketContext = {
      uuid: uuid(),
      proxyToServerWebSocketOptions: undefined,
      proxyToServerWebSocket: undefined,
      isSSL,
      connectRequest:
        self.connectRequests[`${socket.remotePort}:${socket.localPort}`],
      clientToProxyWebSocket: ws,
      onWebSocketConnectionHandlers: [],
      onWebSocketFrameHandlers: [],
      onWebSocketCloseHandlers: [],
      onWebSocketErrorHandlers: [],
      onWebSocketConnection(fn) {
        ctx.onWebSocketConnectionHandlers.push(fn);
        return ctx;
      },
      onWebSocketSend(fn) {
        ctx.onWebSocketFrameHandlers.push(
          function (
            ctx: any,
            type: string,
            fromServer: any,
            data: any,
            flags: any,
            callback: (arg0: null, arg1: any, arg2: any) => void
          ) {
            if (!fromServer && type === 'message') {
              return this(ctx, data, flags, callback);
            } else {
              callback(null, data, flags);
            }
          }.bind(fn)
        );
        return ctx;
      },
      onWebSocketMessage(fn) {
        ctx.onWebSocketFrameHandlers.push(
          function (
            ctx: any,
            type: string,
            fromServer: any,
            data: any,
            flags: any,
            callback: (arg0: null, arg1: any, arg2: any) => void
          ) {
            if (fromServer && type === 'message') {
              return this(ctx, data, flags, callback);
            } else {
              callback(null, data, flags);
            }
          }.bind(fn)
        );
        return ctx;
      },
      onWebSocketFrame(fn) {
        ctx.onWebSocketFrameHandlers.push(fn);
        return ctx;
      },
      onWebSocketClose(fn) {
        ctx.onWebSocketCloseHandlers.push(fn);
        return ctx;
      },
      onWebSocketError(fn) {
        ctx.onWebSocketErrorHandlers.push(fn);
        return ctx;
      },
      use(mod) {
        if (mod.onWebSocketConnection) {
          ctx.onWebSocketConnection(mod.onWebSocketConnection);
        }
        if (mod.onWebSocketSend) {
          ctx.onWebSocketFrame(
            function (
              ctx: any,
              type: string,
              fromServer: any,
              data: any,
              flags: any,
              callback: (arg0: null, arg1: any, arg2: any) => void
            ) {
              if (!fromServer && type === 'message') {
                return this(ctx, data, flags, callback);
              } else {
                callback(null, data, flags);
              }
            }.bind(mod.onWebSocketSend)
          );
        }
        if (mod.onWebSocketMessage) {
          ctx.onWebSocketFrame(
            function (
              ctx: any,
              type: string,
              fromServer: any,
              data: any,
              flags: any,
              callback: (arg0: null, arg1: any, arg2: any) => void
            ) {
              if (fromServer && type === 'message') {
                return this(ctx, data, flags, callback);
              } else {
                callback(null, data, flags);
              }
            }.bind(mod.onWebSocketMessage)
          );
        }
        if (mod.onWebSocketFrame) {
          ctx.onWebSocketFrame(mod.onWebSocketFrame);
        }
        if (mod.onWebSocketClose) {
          ctx.onWebSocketClose(mod.onWebSocketClose);
        }
        if (mod.onWebSocketError) {
          ctx.onWebSocketError(mod.onWebSocketError);
        }
        return ctx;
      }
    };
    const clientToProxyWebSocket = ctx.clientToProxyWebSocket!;
    clientToProxyWebSocket.on(
      'message',
      self._onWebSocketFrame.bind(self, ctx, 'message', false)
    );
    clientToProxyWebSocket.on(
      'ping',
      self._onWebSocketFrame.bind(self, ctx, 'ping', false)
    );
    clientToProxyWebSocket.on(
      'pong',
      self._onWebSocketFrame.bind(self, ctx, 'pong', false)
    );
    clientToProxyWebSocket.on('error', self._onWebSocketError.bind(self, ctx));
    // @ts-ignore
    clientToProxyWebSocket._socket.on(
      'error',
      self._onWebSocketError.bind(self, ctx)
    );
    clientToProxyWebSocket.on(
      'close',
      self._onWebSocketClose.bind(self, ctx, false)
    );
    // @ts-ignore
    clientToProxyWebSocket._socket.pause();

    let url;
    if (upgradeReq.url == '' || /^\//.test(upgradeReq.url!)) {
      const hostPort = OpsiHTTPProxy.parseHostAndPort(upgradeReq);

      const prefix = ctx.isSSL ? 'wss' : 'ws';
      const port = hostPort!.port ? ':' + hostPort!.port : '';
      url = `${prefix}://${hostPort!.host}${port}${upgradeReq.url}`;
    } else {
      url = upgradeReq.url;
    }
    const proxyToServerHeaders: http_headers_t = {};
    const clientToProxyHeaders = upgradeReq.headers;
    for (const header in clientToProxyHeaders) {
      const header_data = clientToProxyHeaders[header];
      if (typeof header !== 'string') continue;
      if (typeof header_data !== 'string') continue;
      if (header.indexOf('sec-websocket') !== 0) {
        proxyToServerHeaders[header] = header_data;
      }
    }

    let protocols: string[] = [];
    if (clientToProxyHeaders['sec-websocket-protocol']) {
      protocols = clientToProxyHeaders['sec-websocket-protocol']
        .split(',')
        .map((p) => p.trim());
    }

    ctx.proxyToServerWebSocketOptions = {
      url,
      protocols: protocols.length > 0 ? protocols : undefined,
      agent: ctx.isSSL ? self.httpsAgent : self.httpAgent,
      headers: proxyToServerHeaders
    };
    function makeProxyToServerWebSocket() {
      ctx.proxyToServerWebSocket = new WebSocket(
        ctx.proxyToServerWebSocketOptions!.url!,
        ctx.proxyToServerWebSocketOptions.protocols,
        ctx.proxyToServerWebSocketOptions
      );
      ctx.proxyToServerWebSocket.on(
        'message',
        self._onWebSocketFrame.bind(self, ctx, 'message', true)
      );
      ctx.proxyToServerWebSocket.on(
        'ping',
        self._onWebSocketFrame.bind(self, ctx, 'ping', true)
      );
      ctx.proxyToServerWebSocket.on(
        'pong',
        self._onWebSocketFrame.bind(self, ctx, 'pong', true)
      );
      ctx.proxyToServerWebSocket.on(
        'error',
        self._onWebSocketError.bind(self, ctx)
      );
      ctx.proxyToServerWebSocket.on(
        'close',
        self._onWebSocketClose.bind(self, ctx, true)
      );
      ctx.proxyToServerWebSocket.on('open', () => {
        // @ts-ignore
        ctx.proxyToServerWebSocket._socket.on(
          'error',
          self._onWebSocketError.bind(self, ctx)
        );
        if (clientToProxyWebSocket!.readyState === WebSocket.OPEN) {
          // @ts-ignore
          clientToProxyWebSocket._socket.resume();
        }
      });
    }

    return self._onWebSocketConnection(ctx, (err) => {
      if (err) {
        return self._onWebSocketError(ctx, err);
      }
      return makeProxyToServerWebSocket();
    });
  }
  */

  /*
  _onHttpServerRequest(
    isSSL: boolean,
    clientToProxyRequest: IncomingMessage,
    proxyToClientResponse: ServerResponse
  ) {
    const self = this;
    const ctx: IContext = {
      uuid: uuid(),
      isSSL,
      serverToProxyResponse: undefined,
      proxyToServerRequestOptions: undefined,
      proxyToServerRequest: undefined,
      connectRequest:
        self.connectRequests[
          `${clientToProxyRequest.socket.remotePort}:${clientToProxyRequest.socket.localPort}`
        ] || undefined,
      clientToProxyRequest,
      proxyToClientResponse,
      onRequestHandlers: [],
      onErrorHandlers: [],
      onRequestDataHandlers: [],
      onResponseHeadersHandlers: [],
      onRequestHeadersHandlers: [],
      onRequestEndHandlers: [],
      onResponseHandlers: [],
      onResponseDataHandlers: [],
      onResponseEndHandlers: [],
      requestFilters: [],
      responseFilters: [],
      responseContentPotentiallyModified: false,
      onRequest(fn) {
        ctx.onRequestHandlers.push(fn);
        return ctx;
      },
      onError(fn) {
        ctx.onErrorHandlers.push(fn);
        return ctx;
      },
      onRequestData(fn) {
        ctx.onRequestDataHandlers.push(fn);
        return ctx;
      },
      onRequestHeaders(fn) {
        ctx.onRequestHeadersHandlers.push(fn);
        return ctx;
      },
      onResponseHeaders(fn) {
        ctx.onResponseHeadersHandlers.push(fn);
        return ctx;
      },
      onRequestEnd(fn) {
        ctx.onRequestEndHandlers.push(fn);
        return ctx;
      },
      addRequestFilter(filter) {
        ctx.requestFilters.push(filter);
        return ctx;
      },
      onResponse(fn) {
        ctx.onResponseHandlers.push(fn);
        return ctx;
      },
      onResponseData(fn) {
        ctx.onResponseDataHandlers.push(fn);
        ctx.responseContentPotentiallyModified = true;
        return ctx;
      },
      onResponseEnd(fn) {
        ctx.onResponseEndHandlers.push(fn);
        return ctx;
      },
      addResponseFilter(filter) {
        ctx.responseFilters.push(filter);
        ctx.responseContentPotentiallyModified = true;
        return ctx;
      },
      use(mod) {
        if (mod.onError) {
          ctx.onError(mod.onError);
        }
        if (mod.onRequest) {
          ctx.onRequest(mod.onRequest);
        }
        if (mod.onRequestHeaders) {
          ctx.onRequestHeaders(mod.onRequestHeaders);
        }
        if (mod.onRequestData) {
          ctx.onRequestData(mod.onRequestData);
        }
        if (mod.onResponse) {
          ctx.onResponse(mod.onResponse);
        }
        if (mod.onResponseData) {
          ctx.onResponseData(mod.onResponseData);
        }
        return ctx;
      }
    };

    ctx.clientToProxyRequest.on(
      'error',
      self._onError.bind(self, 'CLIENT_TO_PROXY_REQUEST_ERROR', ctx)
    );
    ctx.proxyToClientResponse.on(
      'error',
      self._onError.bind(self, 'PROXY_TO_CLIENT_RESPONSE_ERROR', ctx)
    );
    ctx.clientToProxyRequest.pause();
    const hostPort = OpsiHTTPProxy.parseHostAndPort(
      ctx.clientToProxyRequest,
      ctx.isSSL ? 443 : 80
    );
    function proxyToServerRequestComplete(
      serverToProxyResponse: http.IncomingMessage
    ) {
      serverToProxyResponse.on(
        'error',
        self._onError.bind(self, 'SERVER_TO_PROXY_RESPONSE_ERROR', ctx)
      );
      serverToProxyResponse.pause();
      ctx.serverToProxyResponse = serverToProxyResponse;
      return self._onResponse(ctx, (err) => {
        if (err) {
          return self._onError('ON_RESPONSE_ERROR', ctx, err);
        }
        const servToProxyResp = ctx.serverToProxyResponse!;

        if (servToProxyResp.headers['trailer']) {
          servToProxyResp.headers['transfer-encoding'] = 'chunked';
        }

        if (
          self.responseContentPotentiallyModified ||
          ctx.responseContentPotentiallyModified
        ) {
          servToProxyResp.headers['transfer-encoding'] = 'chunked';
          delete servToProxyResp.headers['content-length'];
        }
        if (self.keepAlive) {
          if (ctx.clientToProxyRequest.headers['proxy-connection']) {
            servToProxyResp.headers['proxy-connection'] = 'keep-alive';
            servToProxyResp.headers['connection'] = 'keep-alive';
          }
        } else {
          servToProxyResp.headers['connection'] = 'close';
        }
        return self._onResponseHeaders(ctx, (err) => {
          if (err) {
            return self._onError('ON_RESPONSEHEADERS_ERROR', ctx, err);
          }
          ctx.proxyToClientResponse.writeHead(
            servToProxyResp!.statusCode!,
            OpsiHTTPProxy.filterAndCanonizeHeaders(servToProxyResp.headers)
          );
          // @ts-ignore
          ctx.responseFilters.push(new ProxyFinalResponseFilter(self, ctx));
          let prevResponsePipeElem = servToProxyResp;
          ctx.responseFilters.forEach((filter) => {
            filter.on(
              'error',
              self._onError.bind(self, 'RESPONSE_FILTER_ERROR', ctx)
            );
            prevResponsePipeElem = prevResponsePipeElem.pipe(filter);
          });
          return servToProxyResp.resume();
        });
      });
    }

    function makeProxyToServerRequest() {
      const proto = ctx.isSSL ? https : http;
      ctx.proxyToServerRequest = proto.request(
        ctx.proxyToServerRequestOptions!,
        proxyToServerRequestComplete
      );
      ctx.proxyToServerRequest.on(
        'error',
        self._onError.bind(self, 'PROXY_TO_SERVER_REQUEST_ERROR', ctx)
      );
      ctx.requestFilters.push(new ProxyFinalRequestFilter(self, ctx));
      let prevRequestPipeElem = ctx.clientToProxyRequest;
      ctx.requestFilters.forEach((filter) => {
        filter.on(
          'error',
          self._onError.bind(self, 'REQUEST_FILTER_ERROR', ctx)
        );
        prevRequestPipeElem = prevRequestPipeElem.pipe(filter);
      });
      ctx.clientToProxyRequest.resume();
    }

    if (hostPort === null) {
      ctx.clientToProxyRequest.resume();
      ctx.proxyToClientResponse.writeHead(400, {
        'Content-Type': 'text/html; charset=utf-8'
      });
      ctx.proxyToClientResponse.end('Bad request: Host missing...', 'utf-8');
    } else {
      const headers: http_headers_t = {};
      for (const h in ctx.clientToProxyRequest.headers) {
        // don't forward proxy-headers
        if (!/^proxy-/i.test(h)) {
          const header = ctx.clientToProxyRequest.headers[h];
          if (typeof header === 'string')
            if (typeof h === 'string') headers[h] = header;
        }
      }
      if (this.options.forceChunkedRequest) {
        delete headers['content-length'];
      }

      ctx.proxyToServerRequestOptions = {
        method: ctx.clientToProxyRequest.method!,
        path: ctx.clientToProxyRequest.url!,
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
    }
  }
  */

  /*
  _onRequestHeaders(ctx: IContext, callback: ErrorCallback) {
    async.forEach(
      this.onRequestHeadersHandlers,
      (fn, callback) => fn(ctx, callback),
      callback
    );
  }
  */

  /*
  _onRequest(ctx: IContext, callback: ErrorCallback) {
    async.forEach(
      this.onRequestHandlers.concat(ctx.onRequestHandlers),
      (fn, callback) => fn(ctx, callback),
      callback
    );
  }
  */

  /*
  _onWebSocketConnection(ctx: IWebSocketContext, callback: ErrorCallback) {
    async.forEach(
      this.onWebSocketConnectionHandlers.concat(
        ctx.onWebSocketConnectionHandlers
      ),
      (fn, callback) => fn(ctx, callback),
      callback
    );
  }
  */

  /*
  _onWebSocketFrame(
    ctx: IWebSocketContext,
    type: string,
    fromServer: boolean,
    data: WebSocket.RawData,
    flags?: WebSocketFlags | boolean
  ) {
    const self = this;
    async.forEach(
      this.onWebSocketFrameHandlers.concat(ctx.onWebSocketFrameHandlers),
      (fn, callback: IWebSocketCallback) =>
        fn(ctx, type, fromServer, data, flags, (err, newData, newFlags) => {
          if (err) {
            return callback(err);
          }
          data = newData;
          flags = newFlags;
          return callback(null, data, flags);
        }),
      (err) => {
        if (err) {
          return self._onWebSocketError(ctx, err);
        }
        const destWebSocket = fromServer
          ? ctx.clientToProxyWebSocket!
          : ctx.proxyToServerWebSocket!;
        if (destWebSocket.readyState === WebSocket.OPEN) {
          switch (type) {
            case 'message':
              destWebSocket.send(data, { binary: flags as boolean });
              break;
            case 'ping':
              destWebSocket.ping(data, flags as boolean);
              break;
            case 'pong':
              destWebSocket.pong(data, flags as boolean);
              break;
          }
        } else {
          self._onWebSocketError(
            ctx,
            new Error(
              `Cannot send ${type} because ${
                fromServer ? 'clientToProxy' : 'proxyToServer'
              } WebSocket connection state is not OPEN`
            )
          );
        }
      }
    );
  }
  */

  /*
  _onWebSocketClose(
    ctx: IWebSocketContext,
    closedByServer: boolean,
    code: number,
    message: Buffer
  ) {
    const self = this;
    if (!ctx.closedByServer && !ctx.closedByClient) {
      ctx.closedByServer = closedByServer;
      ctx.closedByClient = !closedByServer;
      async.forEach(
        this.onWebSocketCloseHandlers.concat(ctx.onWebSocketCloseHandlers),
        (fn, callback) => fn(ctx, code, message, callback),
        (err) => {
          if (err) {
            return self._onWebSocketError(ctx, err);
          }
          const clientToProxyWebSocket = ctx.clientToProxyWebSocket!;
          const proxyToServerWebSocket = ctx.proxyToServerWebSocket!;
          if (
            clientToProxyWebSocket.readyState !==
            proxyToServerWebSocket.readyState
          ) {
            try {
              if (
                clientToProxyWebSocket.readyState === WebSocket.CLOSED &&
                proxyToServerWebSocket.readyState === WebSocket.OPEN
              ) {
                if (code === 1005) proxyToServerWebSocket.close();
                else proxyToServerWebSocket.close(code, message);
              } else if (
                proxyToServerWebSocket.readyState === WebSocket.CLOSED &&
                clientToProxyWebSocket.readyState === WebSocket.OPEN
              ) {
                if (code === 1005) proxyToServerWebSocket.close();
                else clientToProxyWebSocket.close(code, message);
              }
            } catch (err: any) {
              return self._onWebSocketError(ctx, err);
            }
          }
        }
      );
    }
  }
  */

  /*
  _onWebSocketError(ctx: IWebSocketContext, err: Error) {
    this.onWebSocketErrorHandlers.forEach((handler) => handler(ctx, err));
    if (ctx) {
      ctx.onWebSocketErrorHandlers.forEach((handler) => handler(ctx, err));
    }
    const clientToProxyWebSocket = ctx.clientToProxyWebSocket!;
    const proxyToServerWebSocket = ctx.proxyToServerWebSocket!;
    if (
      proxyToServerWebSocket &&
      clientToProxyWebSocket.readyState !== proxyToServerWebSocket.readyState
    ) {
      try {
        if (
          clientToProxyWebSocket.readyState === WebSocket.CLOSED &&
          proxyToServerWebSocket.readyState === WebSocket.OPEN
        ) {
          proxyToServerWebSocket.close();
        } else if (
          proxyToServerWebSocket.readyState === WebSocket.CLOSED &&
          clientToProxyWebSocket.readyState === WebSocket.OPEN
        ) {
          clientToProxyWebSocket.close();
        }
      } catch (err) {
        // ignore
      }
    }
  }
  */

  /*
  _onRequestData(
    ctx: IContext,
    chunk: Buffer | undefined,
    callback: (arg0: null, arg1: any) => void
  ) {
    const self = this;
    async.forEach(
      this.onRequestDataHandlers.concat(ctx.onRequestDataHandlers),
      (fn, callback: OnRequestDataCallback) => {
        if (!Buffer.isBuffer(chunk)) return;
        fn(ctx, chunk, (err, newChunk) => {
          if (err) {
            return callback(err);
          }
          chunk = newChunk;
          return callback(null, newChunk);
        });
      },
      (err) => {
        if (err) {
          return self._onError('ON_REQUEST_DATA_ERROR', ctx, err);
        }
        return callback(null, chunk);
      }
    );
  }
  */

  /*
  _onRequestEnd(ctx: IContext, callback: ErrorCallback) {
    const self = this;
    async.forEach(
      this.onRequestEndHandlers.concat(ctx.onRequestEndHandlers),
      (fn, callback) => fn(ctx, callback),
      (err) => {
        if (err) {
          return self._onError('ON_REQUEST_END_ERROR', ctx, err);
        }
        return callback(null);
      }
    );
  }
  */

  /*
  _onResponse(ctx: IContext, callback: ErrorCallback) {
    async.forEach(
      this.onResponseHandlers.concat(ctx.onResponseHandlers),
      (fn, callback) => fn(ctx, callback),
      callback
    );
  }
  */

  /*
  _onResponseHeaders(ctx: IContext, callback: ErrorCallback) {
    async.forEach(
      this.onResponseHeadersHandlers,
      (fn, callback) => fn(ctx, callback),
      callback
    );
  }
  */

  /*
  _onResponseData(
    ctx: IContext,
    chunk: Buffer | undefined,
    callback: ErrorCallback
  ) {
    async.forEach(
      this.onResponseDataHandlers.concat(ctx.onResponseDataHandlers),
      (fn, callback: OnRequestDataCallback) => {
        if (!Buffer.isBuffer(chunk)) return;
        fn(ctx, chunk, (err, newChunk) => {
          if (err) {
            return callback(err);
          }

          chunk = newChunk;
          return callback(null, newChunk);
        });
      },
      (err) => {
        if (err) {
          return this._onError('ON_RESPONSE_DATA_ERROR', ctx, err);
        }
        return callback(null, chunk);
      }
    );
  }
  */

  /*
  _onResponseEnd(ctx: IContext, callback: ErrorCallback) {
    async.forEach(
      this.onResponseEndHandlers.concat(ctx.onResponseEndHandlers),
      (fn, callback) => fn(ctx, callback),
      (err) => {
        if (err) {
          return this._onError('ON_RESPONSE_END_ERROR', ctx, err);
        }
        return callback(null);
      }
    );
  }
  */

  static parseHostAndPort(req: http.IncomingMessage, defaultPort?: number) {
    const m = req.url!.match(/^http:\/\/([^/]+)(.*)/);
    if (m) {
      req.url = m[2] || '/';
      return OpsiHTTPProxy.parseHost(m[1], defaultPort);
    } else if (req.headers.host) {
      return OpsiHTTPProxy.parseHost(req.headers.host, defaultPort);
    } else {
      return null;
    }
  }

  static parseHost(
    hostString: string,
    defaultPort?: number
  ): { host: string; port: number | undefined } {
    const m = hostString.match(/^http:\/\/(.*)/);
    if (m) {
      const parsedUrl = url.parse(hostString);
      return {
        host: parsedUrl.hostname as string,
        port: Number(parsedUrl.port)
      };
    }

    const hostPort = hostString.split(':');
    const host = hostPort[0];
    const port = hostPort.length === 2 ? +hostPort[1] : defaultPort;

    return {
      host,
      port
    };
  }

  /*
  static filterAndCanonizeHeaders(originalHeaders: IncomingHttpHeaders) {
    const headers: http_headers_t = {};
    for (const key in originalHeaders) {
      const canonizedKey = key.trim();
      if (/^public-key-pins/i.test(canonizedKey)) {
        // HPKP header => filter
        continue;
      }
      if (typeof canonizedKey === 'string')
        if (typeof originalHeaders[key] === 'string')
          headers[canonizedKey] = originalHeaders[key];
    }

    return headers;
  }
  */
}

export {
  OpsiHTTPProxy,
  OpsiproxyRequestContext,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_t,
  plugin_method_ret_t,
  opsiproxy_options_t,
  opsiproxy_socket_i
};
