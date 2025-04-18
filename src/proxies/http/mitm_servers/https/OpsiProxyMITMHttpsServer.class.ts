/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-this-alias */
/**
 * When a tunneled proxy request context is created, if the request is detected
 * to be encrypted, we create one of these servers to allow clients to communicate
 * as if they were communicating with a normal HTTPS server.  We use the opsiproxy
 * certificate authority to create a key/cert for the server, and then we create normal
 * https server using the certificates/keys.
 */

import net from 'node:net';
import * as tls from 'tls';
import http from 'node:http';
import https from 'node:https';
import stream from 'node:stream';
import * as stream_promises from 'node:stream/promises';

import { WebSocketServer } from 'ws';

import { Deferred } from '@opsimathically/deferred';
import { AddressInfo } from 'node:net';

import {
  OpsiProxySocketContext,
  opsiproxy_http_proxy_to_client_response_message_i
} from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';

import {
  OpsiHTTPProxy,
  opsiproxy_socket_i,
  opsiproxy_http_incomming_message_i
} from '@src/proxies/http/proxy';

import { OpsiProxyTunnelContext } from '@src/proxies/http/contexts/tunnelling_request_context/OpsiProxyTunnelContext.class';
import { OpsiProxyContext } from '@src/proxies/http/contexts/OpsiProxyContext.class';

type opsiproxy_mitm_https_server_options_t = {
  tunnel_ctx: OpsiProxyTunnelContext;
  hosts: string[];
  port: number;
};

class OpsiProxyMITMHttpsServer {
  listening_port: number = 0;
  addr_info!: AddressInfo;

  https_mitm_server!: https.Server;
  net_mitm_server!: net.Server;

  http_mitm_server!: http.Server;
  tls_mitm_server!: tls.Server;

  connect_relay_stack: any[] = [];

  options: opsiproxy_mitm_https_server_options_t;
  constructor(options: opsiproxy_mitm_https_server_options_t) {
    this.options = options;
  }

  // start the server
  async start(): Promise<boolean> {
    const mitmhttps_ref = this;

    // ensure we have a tunnel context
    if (!mitmhttps_ref?.options?.tunnel_ctx) return false;

    // get proxy ref
    const ctx = this.options.tunnel_ctx.options.parent_ctx;
    const tunnel_ctx = this.options.tunnel_ctx;
    const opsiproxy_ref = ctx.options.proxy;

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Step 0: Create DuplexStream %%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // We first create a duplex stream, this will allow us
    // to mitm the decoded TLS connection.

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Step 1: Create HTTP Server %%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // http_mitm_server!: http.Server;
    // tls_mitm_server!: tls.Server;
    const httpHandler = (
      req: http.IncomingMessage,
      res: http.ServerResponse
    ) => {
      console.log('HTTP request received:', req.method, req.url);
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Hello from inside TLS tunnel\n');
    };

    const httpServer = http.createServer(httpHandler);

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% Step 2: Create TLS Server %%%%%%%%%%%%%%%%%%%
    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

    // generate key and pem set
    const ca_signed_https_pems =
      await opsiproxy_ref.certificate_authority.generateServerCertificateAndKeysPEMSet(
        this.options.hosts
      );

    // ---

    // Prepare TLS options
    const options = {
      key: ca_signed_https_pems.private_key_pem,
      cert: ca_signed_https_pems.cert_pem
    };

    const tls_server = tls.createServer(options);

    async function* readTLSSocket(socket: any) {
      let buffer = Buffer.alloc(0);
      const readHandler = (data: Buffer) => {
        debugger;
        buffer = Buffer.concat([buffer, data]);
      };
      debugger;
      socket.on('data', readHandler);
      socket.on('end', () => {
        socket.off('data', readHandler);
      });

      while (!socket.destroyed || buffer.length > 0) {
        if (buffer.length > 0) {
          const data = buffer;
          buffer = Buffer.alloc(0);
          debugger;
          yield data;
        } else {
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
      }
    }

    tls_server.on('secureConnection', async (socket: tls.TLSSocket) => {
      // get the oldest available
      const _extra_data = mitmhttps_ref.connect_relay_stack.shift();

      httpServer.emit('connection', socket);

      return;
      debugger;

      // Step 1:

      /*
      socket.on('data', (chunk) => {
        debugger;
     
          dataBuffer = Buffer.concat([dataBuffer, chunk]);
      
          const reqString = dataBuffer.toString();
          if (reqString.includes('\r\n\r\n')) {
            console.log('Received HTTPS request:\n', reqString);
      
            const response = [
              'HTTP/1.1 200 OK',
              'Content-Type: text/plain',
              'Content-Length: 13',
              'Connection: close',
              '',
              'Hello, world!',
            ].join('\r\n');
      
            socket.write(response);
            socket.end();
          }
     
      });
      */

      socket.on('error', (err) => {
        console.error('TLS socket error:', err);
      });

      // start the async reader
      const reader = readTLSSocket(socket);

      for await (const data of reader) {
        debugger;
      }
    });

    mitmhttps_ref.tls_mitm_server = tls_server;

    // start the server listening on whatever address is available
    const listen_deferred: Deferred = new Deferred();
    mitmhttps_ref.tls_mitm_server.listen(0, () => {
      // gather port
      mitmhttps_ref.listening_port = (
        mitmhttps_ref.tls_mitm_server.address() as AddressInfo
      ).port;
      // gather addr info
      mitmhttps_ref.addr_info =
        mitmhttps_ref.tls_mitm_server.address() as AddressInfo;

      // resolve
      listen_deferred.resolve(true);
    });

    await listen_deferred.promise;
    // -----

    return true;
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% OLD UNUSED %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  // start the server
  async starOld(): Promise<boolean> {
    const mitmhttps_ref = this;

    // ensure we have a tunnel context
    if (!mitmhttps_ref?.options?.tunnel_ctx) return false;

    // get proxy ref
    const ctx = this.options.tunnel_ctx.options.parent_ctx;
    const tunnel_ctx = this.options.tunnel_ctx;
    const opsiproxy_ref = ctx.options.proxy;

    // generate key and pem set
    const ca_signed_https_pems =
      await opsiproxy_ref.certificate_authority.generateServerCertificateAndKeysPEMSet(
        this.options.hosts
      );

    const httpsServer = new https.Server();

    // create server
    const netServer = net.createServer({
      /*pauseOnConnect: true,*/
      blockList: opsiproxy_ref.options.proxy_incomming_block_list
    });

    // create server options
    const https_server_options: https.ServerOptions = {
      key: ca_signed_https_pems.private_key_pem,
      cert: ca_signed_https_pems.cert_pem
    };

    // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    // %%% OLD OLD OLD

    mitmhttps_ref.https_mitm_server = https.createServer(https_server_options);

    mitmhttps_ref.https_mitm_server.on('error', async (err: Error) => {
      debugger;
    });

    mitmhttps_ref.https_mitm_server.on(
      'clientError',
      async (err: Error, socket: opsiproxy_socket_i) => {
        // 'ERR_SSL_TLSV1_ALERT_UNKNOWN_CA'
        // debugger;
      }
    );

    mitmhttps_ref.https_mitm_server.on(
      'connect',
      (req: http.IncomingMessage, socket: stream.Duplex, head: Buffer) => {
        // debugger;
      }
    );

    mitmhttps_ref.https_mitm_server.on(
      'request',
      (
        // req: IncomingMessage,
        // res: ServerResponse<IncomingMessage> & { req: IncomingMessage }
        client_to_proxy_request: opsiproxy_http_incomming_message_i,
        proxy_to_client_response: opsiproxy_http_proxy_to_client_response_message_i
      ) => {
        // WE GET HERE, THIS GOES BACK, HOLY CRAP YAY

        /*
        proxy_to_client_response.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8'
        });
        proxy_to_client_response.end('MOOOO', 'utf-8');
        */
        debugger;

        /*
        hostname: client_to_proxy_request.host_and_port.host,
            port: client_to_proxy_request.host_and_port.port,
            path:
              ctx.client_to_proxy_request.parsed_request_url.pathname +
              ctx.client_to_proxy_request.parsed_request_url.search,
            method: ctx.client_to_proxy_request.method,
            headers: ctx.client_to_proxy_request.headers
        */

        // tunnel_ctx.options.client_to_proxy.request.host;
        // tunnel_ctx.options.client_to_proxy.request.port;

        const proxyReq = https.request(
          {
            hostname: 'news.ycombinator.com',
            port: 443,
            path: '/',
            method: 'GET',
            rejectUnauthorized: false, // <--- Accept self-signed or invalid certs
            checkServerIdentity: () => undefined
          },
          (res) => {
            debugger;
            // Write the headers and status from the destination to the client
            proxy_to_client_response.writeHead(
              res.statusCode || 500,
              res.headers
            );
            // Pipe the response from target back to the client
            res.pipe(proxy_to_client_response);
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

        /*

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
        */

        /*
          const ctx = (client_to_proxy_request.socket as opsiproxy_socket_i)
            .opsiproxy_socket_ctx;
          if (!ctx) throw new Error('request_with_no_context_is_unreasonable');
  
          if (!client_to_proxy_request?.host_and_port?.host) return;
          if (!client_to_proxy_request?.host_and_port?.port) return;
          */
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
        /*
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
          */
      }
    );

    const wss_mitm_server = new WebSocketServer({
      server: mitmhttps_ref.https_mitm_server
    });
    wss_mitm_server.on(
      'connection',
      (websocket: WebSocket, request: http.IncomingMessage) => {
        debugger;
        /*
        websocket.upgradeReq = req;
        self._onWebSocketServerConnect.call(self, true, ws, req);
        */
      }
    );

    // https.ServerOptions

    // start listening with the https server using localhost and the
    // first available port (port 0 selects any available)

    //listening_port
    const listen_deferred: Deferred = new Deferred();
    mitmhttps_ref.https_mitm_server.listen(
      { port: 0, host: '127.0.0.1' },
      () => {
        // gather port
        mitmhttps_ref.listening_port = (
          mitmhttps_ref.https_mitm_server.address() as AddressInfo
        ).port;

        // gather addr info
        mitmhttps_ref.addr_info =
          mitmhttps_ref.https_mitm_server.address() as AddressInfo;

        // resolve
        listen_deferred.resolve(true);
      }
    );
    await listen_deferred.promise;

    // return indicating that the mitm is in place
    return true;
    /*
    const https_server_options: https.ServerOptions = {
        key: mitm_certs.private_key_pem,
        cert: mitm_certs.cert_pem
      };
  
      const https_mitm_server = https.createServer(https_server_options);
      */
  }
}

export { OpsiProxyMITMHttpsServer };
