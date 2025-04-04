/* eslint-disable @typescript-eslint/no-this-alias */
import { EventEmitter } from 'node:events';

import { randomGuid } from '@opsimathically/randomdatatools';

import { OpsiProxySocketContext } from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';
import { OpsiProxyForwardRequestContext } from '@src/proxies/http/contexts/forward_request_context/OpsiProxyForwardRequestContext.class';
import { OpsiProxyTunnelContext } from '@src/proxies/http/contexts/tunnelling_request_context/OpsiProxyTunnelContext.class';
import { OpsiHTTPProxy } from '../proxy';

// These are all the possible positions a
type opsiproxy_context_position_indicator_t =
  | 'client_to_proxy'
  | 'proxy_to_client'
  | 'proxy_to_remote_server'
  | 'unknown';

type opsiproxy_context_options_t = {
  proxy: OpsiHTTPProxy;
};

type opsiproxy_sub_context_set_t = {
  socket_ctx: OpsiProxySocketContext | null;
  tunnel_ctx: OpsiProxyTunnelContext | null;
};

class OpsiProxyContext extends EventEmitter {
  // global id for this context
  uuid: string;

  // a context can be in multiple states/stages and will have
  // different sub contexts available at each.
  sub_contexts: {
    client_to_proxy: opsiproxy_sub_context_set_t;
    proxy_to_client: opsiproxy_sub_context_set_t;
    proxy_to_remote_server: opsiproxy_sub_context_set_t;
  } = {
    client_to_proxy: {
      socket_ctx: null,
      tunnel_ctx: null
    },
    proxy_to_client: {
      socket_ctx: null,
      tunnel_ctx: null
    },
    proxy_to_remote_server: {
      socket_ctx: null,
      tunnel_ctx: null
    }
  };

  // As a context moves from one stage to another, progress is
  // pushed to this array as a string.  This is meant to be an
  // easy way to determine a reliable indicator of where we are
  // in an context.  This information is useful for debugging
  // as well as for determining if we are in a valid state.
  progress: string[] = [];

  options: opsiproxy_context_options_t;
  constructor(options: opsiproxy_context_options_t) {
    super();
    this.uuid = randomGuid();
    this.options = options;
    this.updateProgress('context__created');
    this.options.proxy.context_map.set(this.uuid, this);
    this.updateProgress('context__added_to_proxy_context_map');
  }

  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Context Settrs %%%%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  setSubContext(params: {
    position: opsiproxy_context_position_indicator_t;
    context:
      | OpsiProxySocketContext
      | OpsiProxyForwardRequestContext
      | OpsiProxyTunnelContext;
  }) {
    const ctx = this;
    if (!params.context) return false;
    if (params.position === 'unknown') return false;

    if (params.context instanceof OpsiProxySocketContext) {
      ctx.sub_contexts[params.position].socket_ctx = params.context;
      ctx.updateProgress(`subcontext_${params.position}__socket_ctx_set`);
    }

    return true;
  }
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
  // %%% Stage Management %%%%%%%%%%%%%%%%%
  // %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

  updateProgress(stage: string) {
    const ctx = this;
    ctx.progress.push(stage);
    return true;
  }
}

export {
  OpsiProxyContext,
  opsiproxy_context_options_t,
  opsiproxy_context_position_indicator_t
};
