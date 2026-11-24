import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, dirname, join, relative } from 'node:path';
import { parseNugetLock, parseMsbuild } from './dotnet.js';
import { parseGoMod } from './go.js';
import { parseGradleLock, parsePom } from './java.js';
import { parsePackageJsonOnly, parsePackageLock, parsePnpmLock, parseYarnLock } from './npm.js';
import { parseComposerLock } from './php.js';
import { parsePipfileLock, parsePoetryLock, parseRequirements, parseUvLock } from './python.js';
import { parseGemfileLock } from './ruby.js';
import { parseCargoLock } from './rust.js';
const SKIP_DIRS = new Set([
    'node_modules', '.git', '.hg', '.svn', '.venv', 'venv', 'env', '.env', '.tox', '.nox', '__pycache__',
    'vendor', 'target', 'dist', 'build', 'out', '.next', '.nuxt', '.svelte-kit', '.turbo', '.cache',
    'bin', 'obj', '.gradle', '.idea', '.vscode', 'coverage', 'site-packages', 'bower_components', '.terraform',
]);
const MAX_DEPTH = 6;
const MAX_FILES = 300;
const LOCK_NAMES = new Set([
    'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock',
    'poetry.lock', 'uv.lock', 'Pipfile.lock', 'go.mod', 'Cargo.lock', 'Gemfile.lock', 'composer.lock',
    'packages.lock.json', 'gradle.lockfile', 'pom.xml', 'Directory.Packages.props', 'package.json',
]);
/** True for any file name pkgguard knows how to read. */
export function isDependencyFile(name) {
    return LOCK_NAMES.has(name) || /^requirements.*\.txt$/i.test(name) || /\.(cs|fs|vb)proj$/i.test(name);
}
function read(p) {
    try {
        return readFileSync(p, 'utf8');
    }
    catch {
        return undefined;
    }
}
function sibling(file, name) {
    return read(join(dirname(file), name));
}
/** Parse one dependency file. `root` is used for the relative `source` path. */
export function parseFile(file, root) {
    const text = read(file);
    if (text === undefined)
        return undefined;
    const name = basename(file);
    const source = relative(root, file).replace(/\\/g, '/') || name;
    const done = (ecosystem, tool, deps, unpinned = 0) => ({ path: source, ecosystem, tool, deps, unpinned });
    const dir = dirname(file);
    const has = (n) => existsSync(join(dir, n));
    switch (name) {
        case 'package-lock.json':
        case 'npm-shrinkwrap.json':
            return done('npm', 'npm', parsePackageLock(text, source, sibling(file, 'package.json')));
        case 'pnpm-lock.yaml':
            return done('npm', 'pnpm', parsePnpmLock(text, source, sibling(file, 'package.json')));
        case 'yarn.lock':
            return done('npm', 'yarn', parseYarnLock(text, source, sibling(file, 'package.json')));
        case 'package.json': {
            if (has('package-lock.json') || has('npm-shrinkwrap.json') || has('pnpm-lock.yaml') || has('yarn.lock') || has('bun.lockb') || has('bun.lock'))
                return undefined;
            const r = parsePackageJsonOnly(text, source);
            return done('npm', 'npm', r.deps, r.unpinned);
        }
        case 'poetry.lock':
            return done('PyPI', 'poetry', parsePoetryLock(text, source, sibling(file, 'pyproject.toml')));
        case 'uv.lock':
            return done('PyPI', 'uv', parseUvLock(text, source, sibling(file, 'pyproject.toml')));
        case 'Pipfile.lock':
            return done('PyPI', 'pipenv', parsePipfileLock(text, source, sibling(file, 'Pipfile')));
        case 'go.mod':
            return done('Go', 'go', parseGoMod(text, source));
        case 'Cargo.lock':
            return done('crates.io', 'cargo', parseCargoLock(text, source));
        case 'Gemfile.lock':
            return done('RubyGems', 'bundler', parseGemfileLock(text, source));
        case 'composer.lock':
            return done('Packagist', 'composer', parseComposerLock(text, source, sibling(file, 'composer.json')));
        case 'packages.lock.json':
            return done('NuGet', 'nuget', parseNugetLock(text, source));
        case 'gradle.lockfile':
            return done('Maven', 'gradle', parseGradleLock(text, source));
        case 'pom.xml': {
            const r = parsePom(text, source);
            return done('Maven', 'maven', r.deps, r.unpinned);
        }
        case 'Directory.Packages.props': {
            const r = parseMsbuild(text, source);
            return done('NuGet', 'nuget', r.deps, r.unpinned);
        }
    }
    if (/\.(cs|fs|vb)proj$/i.test(name)) {
        if (has('packages.lock.json'))
            return undefined;
        const r = parseMsbuild(text, source);
        return done('NuGet', 'nuget', r.deps, r.unpinned);
    }
    if (/\.txt$/i.test(name) && (/^requirements/i.test(name) || /(^|\/)requirements\//i.test(source))) {
        // requirements.txt is the compiled output of requirements.in: read the .txt only
        if (has('poetry.lock') || has('uv.lock') || has('Pipfile.lock'))
            return undefined;
        const r = parseRequirements(text, source);
        return done('PyPI', 'pip', r.deps, r.unpinned);
    }
    return undefined;
}
/** Every dependency file under `root`, skipping vendored / generated folders. */
export function findDependencyFiles(root) {
    const out = [];
    const walk = (dir, depth) => {
        if (out.length >= MAX_FILES)
            return;
        let entries;
        try {
            entries = readdirSync(dir, { withFileTypes: true });
        }
        catch {
            return;
        }
        const inRequirementsDir = basename(dir).toLowerCase() === 'requirements';
        for (const e of entries) {
            if (e.isFile() && (isDependencyFile(e.name) || (inRequirementsDir && /\.txt$/i.test(e.name))))
                out.push(join(dir, e.name));
        }
        if (depth >= MAX_DEPTH)
            return;
        for (const e of entries) {
            if (e.isDirectory() && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.'))
                walk(join(dir, e.name), depth + 1);
        }
    };
    walk(root, 0);
    return out.slice(0, MAX_FILES);
}
export function parseProject(root) {
    const manifests = [];
    const errors = [];
    for (const f of findDependencyFiles(root)) {
        try {
            const m = parseFile(f, root);
            if (m && (m.deps.length || m.unpinned))
                manifests.push(m);
        }
        catch (err) {
            errors.push(`${relative(root, f).replace(/\\/g, '/')}: could not parse (${err.message})`);
        }
    }
    return { manifests, errors };
}
