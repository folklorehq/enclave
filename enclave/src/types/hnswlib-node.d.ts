declare module 'hnswlib-node' {
  export class HierarchicalNSW {
    constructor(space: string, dim: number);
    initIndex(maxElements: number): void;
    readIndex(path: string, allowReplaceDeleted?: boolean): void;
    writeIndex(path: string): void;
    addPoint(vector: number[], label: number): void;
    searchKnn(vector: number[], k: number): { neighbors: number[]; distances: number[] };
    setEf(ef: number): void;
    getEf(): number;
    getMaxElements(): number;
    getCurrentCount(): number;
    getNumDimensions(): number;
    resizeIndex(newMaxElements: number): void;
  }
  export default { HierarchicalNSW };
}
