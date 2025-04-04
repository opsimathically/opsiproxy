// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% OpsiProxyTunnelContextProcessor Class %%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/*
HTTP Proxies use either forward requests, or tunnels.  This class
handles the context in which a tunnel is made.
*/

import { OpsiHTTPProxy } from '@src/proxies/http/OpsiHTTPProxy.class.js';

type proxy_tunnel_context_options_t = {
  proxy: OpsiHTTPProxy;
};

class OpsiProxyTunnelContextProcessor {
  options: proxy_tunnel_context_options_t;

  constructor(options: proxy_tunnel_context_options_t) {
    this.options = options;
  }
}

export { OpsiProxyTunnelContextProcessor };
