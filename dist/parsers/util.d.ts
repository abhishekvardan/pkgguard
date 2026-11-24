/**
 * Shared helpers for lockfile parsers. Deliberately small, dependency-free readers that
 * understand exactly the subset of YAML / TOML that lockfiles use.
 */
/** Shortest chain from any root to each node, excluding the node itself: name -> [direct, ..., parent]. */
export declare function viaPaths(graph: Map<string, Iterable<string>>, roots: Iterable<string>): Map<string, string[]>;
export declare function unquote(s: string): string;
/**
 * Block-style YAML mapping reader (enough for pnpm-lock.yaml): nested maps of scalars.
 * Sequences become arrays of scalars; flow collections stay strings.
 */
export declare function parseSimpleYaml(text: string): any;
export interface TomlTable {
    header: string;
    /** Set for [[array-of-tables]] entries. */
    array: boolean;
    values: Record<string, string | string[]>;
}
/**
 * Line-oriented TOML reader for lockfiles: returns tables in file order. Values are raw
 * strings (quotes removed); arrays become string arrays; inline tables stay raw text.
 */
export declare function parseTomlTables(text: string): TomlTable[];
/** Read `key = "value"` from a TOML inline table such as `{ name = "x", version = "1" }`. */
export declare function inlineField(inline: string, key: string): string | undefined;
export declare function readJson(text: string): any;
