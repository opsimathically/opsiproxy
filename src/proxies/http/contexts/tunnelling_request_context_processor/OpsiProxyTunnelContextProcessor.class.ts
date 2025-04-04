// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% OpsiProxyTunnelContextProcessor Class %%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/*
HTTP Proxies use either forward requests, or tunnels.  This class
handles the context in which a tunnel is made.
*/

import { OpsiHTTPProxy } from '@src/proxies/http/proxy';
import { OpsiProxyNetContext } from '@src/proxies/http/contexts/OpsiProxyNetContext.class';
import { EventEmitter } from 'stream';

type proxy_tunnel_context_options_t = {
  proxy: OpsiHTTPProxy;
  net_context: OpsiProxyNetContext;
};

class OpsiProxyTunnelContextProcessor extends EventEmitter {
  options: proxy_tunnel_context_options_t;

  constructor(options: proxy_tunnel_context_options_t) {
    super();
    this.options = options;
  }
}

export { OpsiProxyTunnelContextProcessor };
