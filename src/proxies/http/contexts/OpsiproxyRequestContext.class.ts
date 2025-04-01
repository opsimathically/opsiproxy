import { randomGuid } from '@opsimathically/randomdatatools';

class OpsiproxyRequestContext {
  uuid: string = randomGuid();
  isSSL: boolean = false;
  serverToProxyResponse!: any;
  proxyToServerRequestOptions!: any;
  proxyToServerRequest!: any;
  connectRequest!: any;
  clientToProxyRequest!: any;
  proxyToClientResponse!: any;
  responseContentPotentiallyModified!: boolean;

  constructor() {}
}

export { OpsiproxyRequestContext };
