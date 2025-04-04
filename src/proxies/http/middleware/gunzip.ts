import zlib from 'zlib';
import type { IContext } from '../types';

export default {
  onResponse(ctx: IContext, callback: Function) {
    const server_to_proxy_response = ctx.server_to_proxy_response!;
    if (
      server_to_proxy_response.headers['content-encoding']?.toLowerCase() ==
      'gzip'
    ) {
      delete server_to_proxy_response.headers['content-encoding'];
      ctx.addResponseFilter(zlib.createGunzip());
    }
    return callback();
  },
  onRequest(ctx: IContext, callback: Function) {
    ctx.proxy_to_server_request_options!.headers['accept-encoding'] = 'gzip';
    return callback();
  }
};
