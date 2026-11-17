import { helpCenterSourceErrorCodeSchema } from '@folklore/contracts/help-center';

export class HelpCenterSourceKindUnsupportedError extends Error {
  constructor() {
    super(helpCenterSourceErrorCodeSchema.enum.source_kind_unsupported);
    this.name = 'HelpCenterSourceKindUnsupportedError';
  }
}

export class HelpCenterNotActivatedError extends Error {
  constructor() {
    super(helpCenterSourceErrorCodeSchema.enum.help_center_not_activated);
    this.name = 'HelpCenterNotActivatedError';
  }
}

export class HelpCenterPlaceKeyUnavailableError extends Error {
  constructor() {
    super(helpCenterSourceErrorCodeSchema.enum.place_key_unavailable);
    this.name = 'HelpCenterPlaceKeyUnavailableError';
  }
}

export class HelpCenterSourceProviderUnavailableError extends Error {
  constructor() {
    super(helpCenterSourceErrorCodeSchema.enum.source_provider_unavailable);
    this.name = 'HelpCenterSourceProviderUnavailableError';
  }
}
