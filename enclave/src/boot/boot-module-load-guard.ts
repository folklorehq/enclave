import { ModuleLoadGuard } from './ModuleLoadGuard.js';

/** The guard boot.ts installs and the composition root releases once its imports have loaded. */
export const bootModuleLoadGuard = new ModuleLoadGuard();
