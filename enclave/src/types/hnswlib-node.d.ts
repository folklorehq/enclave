declare module 'hnswlib-node' {
  export class HierarchicalNSW {
    constructor(space: string, dim: number);
    initIndex(maxElements: number): void;
    readIndex(path: string, maxElements: number): void;
    writeIndex(path: string): void;
    addPoint(vector: number[], label: number): void;
    searchKnn(vector: number[], k: number): { neighbors: number[]; distances: number[] };
    getMaxElements(): number;
    getCurrentCount(): number;
    resizeIndex(newMaxElements: number): void;
  }
  export default { HierarchicalNSW };
}
