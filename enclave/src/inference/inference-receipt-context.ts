import { AsyncLocalStorage } from 'node:async_hooks';

export interface InferenceReceiptContext {
  canary_run_id: string;
  request_id: string;
}

const storage = new AsyncLocalStorage<InferenceReceiptContext>();

export function withInferenceReceiptContext<T>(
  context: InferenceReceiptContext | undefined,
  callback: () => Promise<T>,
): Promise<T> {
  return context ? storage.run(context, callback) : callback();
}

export function currentInferenceReceiptContext(): InferenceReceiptContext | undefined {
  return storage.getStore();
}
