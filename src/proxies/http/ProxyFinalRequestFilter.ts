/* eslint-disable @typescript-eslint/no-explicit-any */
import events from 'events';

export class ProxyFinalRequestFilter extends events.EventEmitter {
  writable: boolean;
  write: any;
  end: any;

  constructor(proxy, ctx) {
    super();
    this.writable = true;
    this.write = (chunk) => {
      proxy._onRequestData(ctx, chunk, (err, chunk) => {
        if (err) {
          return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
        }
        if (chunk) {
          return ctx.proxy_to_server_request.write(chunk);
        }
      });
      return true;
    };

    this.end = (chunk) => {
      if (chunk) {
        return proxy._onRequestData(ctx, chunk, (err, chunk) => {
          if (err) {
            return proxy._onError('ON_REQUEST_DATA_ERROR', ctx, err);
          }

          return proxy._onRequestEnd(ctx, (err) => {
            if (err) {
              return proxy._onError('ON_REQUEST_END_ERROR', ctx, err);
            }
            return ctx.proxy_to_server_request.end(chunk);
          });
        });
      } else {
        return proxy._onRequestEnd(ctx, (err) => {
          if (err) {
            return proxy._onError('ON_REQUEST_END_ERROR', ctx, err);
          }
          return ctx.proxy_to_server_request.end(chunk || undefined);
        });
      }
    };
  }
}
