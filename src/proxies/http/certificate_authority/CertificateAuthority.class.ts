/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-unsafe-function-type */
/* eslint-disable @typescript-eslint/no-this-alias */
/* eslint-disable @typescript-eslint/no-explicit-any */

// TODO: We're going to want to go through this code and modernize it,
// and provide additional capabilities for certificate generation naming
// convention.  Right now, certficate names reference host names, but
// that is not a reasonable thing from a sanity/security perspective,
// since there are potential edge cases where a host name could be
// attacker controlled.  I'd like to use a hash of the host name instead,
// as it's guaranteed to match the host, as well as removing he hostname
// as an attack vector.
//
// We may also want to move certification generation to a worker thread,
// since it can be a bit slow, and we don't want to block the main thread.

// import fs promises api
import * as fs_promises from 'node:fs/promises';

// old imports
import FS from 'fs';
import path from 'node:path';
import Forge from 'node-forge';
const { pki, md } = Forge;
import { mkdirp } from 'mkdirp';
import async from 'async';
import ErrnoException = NodeJS.ErrnoException;

const CAattrs = [
  {
    name: 'commonName',
    value: 'NodeMITMProxyCA'
  },
  {
    name: 'countryName',
    value: 'Internet'
  },
  {
    shortName: 'ST',
    value: 'Internet'
  },
  {
    name: 'localityName',
    value: 'Internet'
  },
  {
    name: 'organizationName',
    value: 'Node MITM Proxy CA'
  },
  {
    shortName: 'OU',
    value: 'CA'
  }
];

const CAextensions = [
  {
    name: 'basicConstraints',
    cA: true
  },
  {
    name: 'keyUsage',
    keyCertSign: true,
    digitalSignature: true,
    nonRepudiation: true,
    keyEncipherment: true,
    dataEncipherment: true
  },
  {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: true,
    emailProtection: true,
    timeStamping: true
  },
  {
    name: 'nsCertType',
    client: true,
    server: true,
    email: true,
    objsign: true,
    sslCA: true,
    emailCA: true,
    objCA: true
  },
  {
    name: 'subjectKeyIdentifier'
  }
];

const ServerAttrs = [
  {
    name: 'countryName',
    value: 'Internet'
  },
  {
    shortName: 'ST',
    value: 'Internet'
  },
  {
    name: 'localityName',
    value: 'Internet'
  },
  {
    name: 'organizationName',
    value: 'Node MITM Proxy CA'
  },
  {
    shortName: 'OU',
    value: 'Node MITM Proxy Server Certificate'
  }
];

const ServerExtensions = [
  {
    name: 'basicConstraints',
    cA: false
  },
  {
    name: 'keyUsage',
    keyCertSign: false,
    digitalSignature: true,
    nonRepudiation: false,
    keyEncipherment: true,
    dataEncipherment: true
  },
  {
    name: 'extKeyUsage',
    serverAuth: true,
    clientAuth: true,
    codeSigning: false,
    emailProtection: false,
    timeStamping: false
  },
  {
    name: 'nsCertType',
    client: true,
    server: true,
    email: false,
    objsign: false,
    sslCA: false,
    emailCA: false,
    objCA: false
  },
  {
    name: 'subjectKeyIdentifier'
  }
] as any[];

type ca_options_t = {
  ca_folder: string;
};

export class CertficateAuthority {
  // base folder for the CA
  base_ca_folder!: string;

  // cert folder (where certs are stored)
  certs_folder!: string;

  // keys folder (where keys are stored)
  keys_folder!: string;

  // certificate authority cert and keys
  ca_cert!: ReturnType<typeof Forge.pki.createCertificate>;
  ca_keys!: ReturnType<typeof Forge.pki.rsa.generateKeyPair>;

  constructor(options: ca_options_t) {
    this.base_ca_folder = options.ca_folder;
    this.certs_folder = path.join(this.base_ca_folder, 'certs');
    this.keys_folder = path.join(this.base_ca_folder, 'keys');
  }

  // Initialize the CA
  async init() {
    const ca_ref = this;

    // check for and create folders if they don't exist
    await mkdirp(ca_ref.base_ca_folder);
    await mkdirp(ca_ref.certs_folder);
    await mkdirp(ca_ref.keys_folder);

    // fs_promises

    /*
    async.series(
      [
        (callback) => {
          const exists = FS.existsSync(path.join(ca.certs_folder, 'ca.pem'));
          if (exists) {
            ca.loadCA(callback);
          } else {
            ca.generateCA(callback);
          }
        }
      ],
      (err) => {
        if (err) {
          return callback(err);
        }
        return callback(null, ca);
      }
    );
    */
  }

  static async create(ca_folder: any, callback: any) {
    const ca = new CertficateAuthority();
    ca.base_ca_folder = ca_folder;
    ca.certs_folder = path.join(ca.base_ca_folder, 'certs');
    ca.keys_folder = path.join(ca.base_ca_folder, 'keys');
    await mkdirp(ca.base_ca_folder);
    await mkdirp(ca.certs_folder);
    await mkdirp(ca.keys_folder);

    async.series(
      [
        (callback) => {
          const exists = FS.existsSync(path.join(ca.certs_folder, 'ca.pem'));
          if (exists) {
            ca.loadCA(callback);
          } else {
            ca.generateCA(callback);
          }
        }
      ],
      (err) => {
        if (err) {
          return callback(err);
        }
        return callback(null, ca);
      }
    );
  }

  randomSerialNumber() {
    // generate random 16 bytes hex string
    let sn = '';
    for (let i = 0; i < 4; i++) {
      sn += `00000000${Math.floor(Math.random() * 256 ** 4).toString(
        16
      )}`.slice(-8);
    }
    return sn;
  }

  getPem() {
    return pki.certificateToPem(this.ca_cert);
  }

  generateCA(
    callback: (
      err?: ErrnoException | null | undefined,
      results?: unknown[] | undefined
    ) => void
  ) {
    const self = this;
    pki.rsa.generateKeyPair({ bits: 2048 }, (err, keys) => {
      if (err) {
        return callback(err);
      }
      const cert = pki.createCertificate();
      cert.publicKey = keys.publicKey;
      cert.serialNumber = self.randomSerialNumber();
      cert.validity.notBefore = new Date();
      cert.validity.notBefore.setDate(cert.validity.notBefore.getDate() - 1);
      cert.validity.notAfter = new Date();
      cert.validity.notAfter.setFullYear(
        cert.validity.notBefore.getFullYear() + 1
      );
      cert.setSubject(CAattrs);
      cert.setIssuer(CAattrs);
      cert.setExtensions(CAextensions);
      cert.sign(keys.privateKey, md.sha256.create());
      self.ca_cert = cert;
      self.ca_keys = keys;

      const tasks = [
        FS.writeFile.bind(
          null,
          path.join(self.certs_folder, 'ca.pem'),
          pki.certificateToPem(cert)
        ),
        FS.writeFile.bind(
          null,
          path.join(self.keys_folder, 'ca.private.key'),
          pki.privateKeyToPem(keys.privateKey)
        ),
        FS.writeFile.bind(
          null,
          path.join(self.keys_folder, 'ca.public.key'),
          pki.publicKeyToPem(keys.publicKey)
        )
      ];
      async.parallel(tasks, callback);
    });
  }

  loadCA(callback: Function) {
    const self = this;
    async.auto(
      {
        certPEM(callback) {
          FS.readFile(
            path.join(self.certs_folder, 'ca.pem'),
            'utf-8',
            callback
          );
        },
        keyPrivatePEM(callback) {
          FS.readFile(
            path.join(self.keys_folder, 'ca.private.key'),
            'utf-8',
            callback
          );
        },
        keyPublicPEM(callback) {
          FS.readFile(
            path.join(self.keys_folder, 'ca.public.key'),
            'utf-8',
            callback
          );
        }
      },
      (
        err,
        results:
          | { certPEM: string; keyPrivatePEM: string; keyPublicPEM: string }
          | undefined
      ) => {
        if (err) {
          return callback(err);
        }
        self.ca_cert = pki.certificateFromPem(results!.certPEM);
        self.ca_keys = {
          privateKey: pki.privateKeyFromPem(results!.keyPrivatePEM),
          publicKey: pki.publicKeyFromPem(results!.keyPublicPEM)
        };
        return callback();
      }
    );
  }

  async generateServerCertificateKeys(hosts: string | string[]) {
    const self = this;
    if (typeof hosts === 'string') {
      hosts = [hosts];
    }
    const mainHost = hosts[0];

    const keysServer = pki.rsa.generateKeyPair(2048);
    const certServer = pki.createCertificate();

    certServer.publicKey = keysServer.publicKey;
    certServer.serialNumber = this.randomSerialNumber();
    certServer.validity.notBefore = new Date();
    certServer.validity.notBefore.setDate(
      certServer.validity.notBefore.getDate() - 1
    );
    certServer.validity.notAfter = new Date();
    certServer.validity.notAfter.setFullYear(
      certServer.validity.notBefore.getFullYear() + 1
    );

    const attrsServer = ServerAttrs.slice(0);
    attrsServer.unshift({
      name: 'commonName',
      value: mainHost
    });

    certServer.setSubject(attrsServer);
    certServer.setIssuer(this.ca_cert.issuer.attributes);
    certServer.setExtensions(
      ServerExtensions.concat([
        {
          name: 'subjectAltName',
          altNames: hosts.map((host) => {
            if (host.match(/^[\d.]+$/)) {
              return { type: 7, ip: host };
            }
            return { type: 2, value: host };
          })
        }
      ])
    );

    certServer.sign(this.ca_keys.privateKey, md.sha256.create());
    const certPem = pki.certificateToPem(certServer);
    const keyPrivatePem = pki.privateKeyToPem(keysServer.privateKey);
    const keyPublicPem = pki.publicKeyToPem(keysServer.publicKey);

    const pem_set = {
      cert_pem: certPem,
      private_key_pem: keyPrivatePem,
      public_key_pem: keyPublicPem
    };

    // code was cut here

    debugger;
    // return the pem set
    return pem_set;
  }

  getCACertPath() {
    return `${this.certs_folder}/ca.pem`;
  }
}

export default CertficateAuthority;
