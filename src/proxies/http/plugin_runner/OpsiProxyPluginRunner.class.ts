/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable no-debugger */
import { OpsiProxySocketContext } from '@src/proxies/http/contexts/socket_context/OpsiProxySocketContext.class';
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
  net_server_behavior:
    | 'go_next_stage'
    | 'stop_at_this_stage'
    | 'destroy_context_and_exit_stage';
  http_server_behavior:
    | 'go_next_stage'
    | 'stop_at_this_stage'
    | 'destroy_context_and_exit_stage';
  activations: opsiproxy_plugin_activation_t[];
};

class OpsiProxyPluginRunner {
  constructor() {}

  async runPluginsBasedOnContext(params: {
    ctx: OpsiProxySocketContext;
    opsiproxy_ref: OpsiHTTPProxy;
  }): Promise<opsiproxy_plugin_runner_run_info_t> {
    const pluginrunner_ref = this;

    const run_info: opsiproxy_plugin_runner_run_info_t = {
      plugin_route: {
        proxy_server: 'unknown',
        label: 'unknown_context_state'
      },
      net_server_behavior: 'go_next_stage',
      http_server_behavior: 'go_next_stage',
      activations: []
    };

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

      // if the plugin did nothing, just go next
      if (plugin_ret.behavior === 'noop') continue;

      // store the activation
      run_info.activations.push({
        plugin_name: plugin_info.name,
        activation: plugin_ret
      });

      // if this was handled, just break and go to the next stage
      if (plugin_ret.behavior === 'handled') break;

      switch (plugin_ret.behavior) {
        case 'continue_to_next_plugin':
          break;

        case 'terminate_context':
          run_info.net_server_behavior = 'destroy_context_and_exit_stage';
          return run_info;

        case 'stop_at_this_stage':
          run_info.net_server_behavior = 'stop_at_this_stage';
          break;

        case 'go_next_stage':
          run_info.net_server_behavior = 'go_next_stage';
          return run_info;

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
    ctx: OpsiProxySocketContext
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

export {
  OpsiProxyPluginRunner,
  opsiproxy_plugin_runner_run_info_t,
  opsiproxy_plugin_activation_t,
  opsiproxy_plugin_runner_routable_label_info_t
};
