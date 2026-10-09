import { bootModuleLoadGuard } from './boot/boot-module-load-guard.js';

// Static imports load before any statement runs, so index.ts cannot report its own graph failing.
bootModuleLoadGuard.install();
await import('./index.js');
