// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% OpsiProxyForwardRequestContextProcessor Class %%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

/*
HTTP Proxies use either forward requests, or tunnels.  This class
handles the context in which a forward request is made.
*/

import { OpsiHTTPProxy } from '@src/proxies/http/proxy';
import { OpsiProxySocketContext } from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';
import { EventEmitter } from 'stream';

type opsiproxy_forward_request_context_options_t = {
  proxy: OpsiHTTPProxy;
  client_to_proxy: {
    net_context: OpsiProxySocketContext;
  };
};

class OpsiProxyForwardRequestContext extends EventEmitter {
  type: string = 'forward_request_ctx';
  options: opsiproxy_forward_request_context_options_t;
  constructor(options: opsiproxy_forward_request_context_options_t) {
    super();
    this.options = options;
  }

  // start the context processor
  async start() {}
}

export {
  OpsiProxyForwardRequestContext,
  opsiproxy_forward_request_context_options_t
};
