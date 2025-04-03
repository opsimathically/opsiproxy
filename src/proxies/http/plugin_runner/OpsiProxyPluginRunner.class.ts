/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable no-debugger */
import { OpsiProxyNetContext } from '@src/proxies/http/contexts/OpsiProxyNetContext.class';
import {
  OpsiHTTPProxy,
  opsiproxy_plugin_info_t,
  opsiproxy_plugin_method_ret_t,
  opsiproxy_plugin_event_cb_t
} from '@src/proxies/http/proxy';

import equal from 'deep-equal';

type opsiproxy_plugin_runner_routable_label_info_t = {
  proxy_server: 'net' | 'http' | 'unknown';
  label:
    | 'net_proxy__client_to_proxy__initial_connection'
    | 'unknown_context_state';
};

type opsiproxy_plugin_activation_t = {
  plugin_name: string;
  activation: opsiproxy_plugin_method_ret_t;
};

type opsiproxy_plugin_runner_run_info_t = {
  plugin_route: opsiproxy_plugin_runner_routable_label_info_t;
  net_server_behavior: {
    terminate: boolean;
    continue: boolean;
  };
  http_server_behavior: {
    terminate: boolean;
    continue: boolean;
  };
  activations: opsiproxy_plugin_activation_t[];
};

class OpsiProxyPluginRunner {
  constructor() {}

  async runPluginsBasedOnContext(params: {
    ctx: OpsiProxyNetContext;
    opsiproxy_ref: OpsiHTTPProxy;
  }): Promise<opsiproxy_plugin_runner_run_info_t> {
    const pluginrunner_ref = this;

    const run_info: opsiproxy_plugin_runner_run_info_t = {
      plugin_route: {
        proxy_server: 'unknown',
        label: 'unknown_context_state'
      },
      net_server_behavior: {
        terminate: false,
        continue: true
      },
      http_server_behavior: {
        terminate: false,
        continue: true
      },
      activations: []
    };

    // ensure we have plugins to run
    if (!params?.opsiproxy_ref?.options?.plugins) return run_info;

    // Determine appropriate event context state to
    // find proper route to plugins.

    const routable_label_info = await pluginrunner_ref.contextToRoutableLabel(
      params.ctx
    );
    if (routable_label_info.label === 'unknown_context_state') {
      throw new Error('unknown_context_state');
      debugger;
    }

    // set the plugin route
    run_info.plugin_route = routable_label_info;

    for (
      let idx = 0;
      idx < params.opsiproxy_ref.options.plugins.length;
      idx++
    ) {
      // gather plugin
      const plugin = params.opsiproxy_ref.options.plugins[idx];

      // if the plugin has no matching method, continue
      if (
        !(plugin as unknown as Record<string, opsiproxy_plugin_event_cb_t>)[
          routable_label_info.label
        ]
      )
        continue;

      // gather plugin info member
      const plugin_info: opsiproxy_plugin_info_t = (
        plugin as unknown as Record<string, opsiproxy_plugin_info_t>
      )['info'];

      // run the event handler
      const plugin_ret: opsiproxy_plugin_method_ret_t = await (
        plugin as unknown as Record<string, opsiproxy_plugin_event_cb_t>
      )[routable_label_info.label](params.ctx);

      // store the activation
      run_info.activations.push({
        plugin_name: plugin_info.name,
        activation: plugin_ret
      });

      switch (plugin_ret.behavior) {
        case 'continue':
          break;
        case 'end':
          break;
        case 'go_next_stage':
          break;
        case 'handled':
          break;
        case 'noop':
          break;
        default:
          break;
      }
      debugger;
    }

    // params.ctx.http_events_history

    // equal
    return run_info;
  }

  // Determine where to route the plugin runner based on available context stages
  async contextToRoutableLabel(
    ctx: OpsiProxyNetContext
  ): Promise<opsiproxy_plugin_runner_routable_label_info_t> {
    const ret_data = {
      proxy_server: 'net',
      label: 'net_proxy__client_to_proxy__initial_connection'
    };

    // net_proxy__client_to_proxy__initial_connection
    if (equal(ctx.stage, ['client_to_proxy__connection'])) {
      return {
        proxy_server: 'net',
        label: 'net_proxy__client_to_proxy__initial_connection'
      };
    }

    // unknown state detected
    return {
      proxy_server: 'unknown',
      label: 'unknown_context_state'
    };
  }
}

export { OpsiProxyPluginRunner };
