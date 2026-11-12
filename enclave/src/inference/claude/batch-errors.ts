export class BatchPendingError extends Error {
  constructor() {
    super('batch_pending');
    this.name = 'BatchPendingError';
  }
}

export class BatchObsoleteError extends Error {
  constructor() {
    super('batch_obsolete');
    this.name = 'BatchObsoleteError';
  }
}
