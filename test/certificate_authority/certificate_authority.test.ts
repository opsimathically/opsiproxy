/* eslint-disable no-debugger */
/* eslint-disable @typescript-eslint/no-unused-vars */
/* eslint-disable @typescript-eslint/no-explicit-any */
import test from 'node:test';
import assert from 'node:assert';
import { deepEqual } from 'fast-equals';

import { CertificateAuthority } from '@src/proxies/http/certificate_authority/CertificateAuthority.class';

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%% Test Definitions %%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

(async function () {
  test('Create CertificateAuthority.', async function () {
    const certificate_authority = new CertificateAuthority();
  });
})();
