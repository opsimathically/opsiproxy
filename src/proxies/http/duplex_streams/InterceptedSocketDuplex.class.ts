import { Duplex } from 'node:stream';

class InterceptedSocketDuplex extends Duplex {
  head_data!: Buffer;
  intercepted_socket: any;
  options!: any;

  // class constructor
  constructor(options) {
    super(options);
  }

  _write(chunk: Buffer, encoding, callback) {
    debugger;
    // run callback indicating write has completed
    callback();
  }

  _read(size: number) {
    debugger;
    this.push(Buffer.from('some_data_of_correct_size'));
  }
}

export { InterceptedSocketDuplex };
