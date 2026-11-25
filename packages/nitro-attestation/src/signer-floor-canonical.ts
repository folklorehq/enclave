import { createHash } from 'node:crypto';

import {
  canonicalJson,
  signerFloorBootstrapSubjectArrayV1,
  signerFloorCommitSubjectArrayV1,
  type SignerFloorBootstrapSubjectInputV1,
  type SignerFloorCommitSubjectV1,
} from '@folklore/contracts';

import { canonicalCbor } from './canonical-cbor.js';
