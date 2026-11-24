import type { Dep } from '../types.js';
/** packages.lock.json (NuGet lock file). */
export declare function parseNugetLock(text: string, source: string): Dep[];
/**
 * *.csproj / *.fsproj / *.vbproj / Directory.Packages.props — PackageReference and
 * PackageVersion items with a literal version.
 */
export declare function parseMsbuild(text: string, source: string): {
    deps: Dep[];
    unpinned: number;
};
