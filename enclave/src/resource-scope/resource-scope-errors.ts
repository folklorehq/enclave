import { RESOURCE_SCOPE_ERROR_CODES } from '@folklore/contracts';

export class ResourceScopeConflictError extends Error {
  constructor() {
    super(RESOURCE_SCOPE_ERROR_CODES.conflict);
    this.name = 'ResourceScopeConflictError';
  }
}

export class ResourceScopeInvalidError extends Error {
  constructor() {
    super(RESOURCE_SCOPE_ERROR_CODES.invalid);
    this.name = 'ResourceScopeInvalidError';
  }
}

export class ResourceScopeUnavailableError extends Error {
  constructor() {
    super(RESOURCE_SCOPE_ERROR_CODES.unavailable);
    this.name = 'ResourceScopeUnavailableError';
  }
}
