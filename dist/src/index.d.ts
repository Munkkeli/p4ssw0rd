export interface HashOptions {
    cost: number;
}
export declare const hash: (password: string, options?: Partial<HashOptions> | undefined) => string;
export declare const check: (password: string, hash: string, options?: Partial<HashOptions> | undefined) => boolean;
export declare const simulate: (options?: Partial<HashOptions> | undefined) => void;
