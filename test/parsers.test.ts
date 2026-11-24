import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { findDependencyFiles, parseFile, parseProject } from '../src/parsers/detect.js';
import type { Dep } from '../src/types.js';

const FX = join(__dirname, 'fixtures');

function depsOf(dir: string, file: string): Dep[] {
  const m = parseFile(join(FX, dir, file), join(FX, dir));
  if (!m) throw new Error(`not parsed: ${dir}/${file}`);
  return m.deps;
}

const find = (deps: Dep[], name: string) => deps.find((d) => d.name === name);

describe('npm', () => {
  it('package-lock v3: versions, direct/transitive, dev, via path, skips links', () => {
    const deps = depsOf('npm', 'package-lock.json');
    expect(deps.map((d) => d.name).sort()).toEqual(['brace-expansion', 'lodash', 'minimatch', 'minimist', 'mkdirp']);
    expect(find(deps, 'lodash')).toMatchObject({ version: '4.17.15', direct: true, dev: false, tool: 'npm' });
    expect(find(deps, 'minimist')).toMatchObject({ version: '0.0.8', direct: false, dev: false, via: ['mkdirp'] });
    expect(find(deps, 'minimatch')).toMatchObject({ direct: true, dev: true });
    expect(find(deps, 'brace-expansion')).toMatchObject({ direct: false, dev: true, via: ['minimatch'] });
  });

  it('pnpm v9: importers, peer suffixes, snapshots graph', () => {
    const deps = depsOf('pnpm', 'pnpm-lock.yaml');
    expect(find(deps, 'axios')).toMatchObject({ version: '0.21.0', direct: true, dev: false, tool: 'pnpm' });
    expect(find(deps, '@babel/traverse')).toMatchObject({ version: '7.22.0', direct: true, dev: true });
    expect(find(deps, 'follow-redirects')).toMatchObject({ version: '1.13.0', direct: false, via: ['axios'] });
  });

  it('yarn v1 with scoped deps', () => {
    const deps = depsOf('yarn', 'yarn.lock');
    expect(find(deps, 'node-fetch')).toMatchObject({ version: '2.6.0', direct: true, tool: 'yarn' });
    expect(find(deps, '@scope/whatwg-url')).toMatchObject({ version: '5.0.0', direct: false, via: ['node-fetch'] });
  });

  it('yarn berry skips workspace and patch entries', () => {
    const deps = depsOf('yarn-berry', 'yarn.lock');
    expect(deps.map((d) => `${d.name}@${d.version}`)).toEqual(['ws@7.4.5']);
  });

  it('package.json next to a lockfile is ignored', () => {
    expect(parseFile(join(FX, 'npm', 'package.json'), join(FX, 'npm'))).toBeUndefined();
  });
});

describe('python', () => {
  it('requirements.txt: pins, pip-compile via, extras/markers, unpinned count', () => {
    const m = parseFile(join(FX, 'python', 'requirements.txt'), join(FX, 'python'))!;
    expect(m.unpinned).toBe(1); // flask>=2.0
    expect(find(m.deps, 'requests')).toMatchObject({ version: '2.19.0', direct: true });
    expect(find(m.deps, 'urllib3')).toMatchObject({ version: '1.23', direct: false, via: ['requests'] });
    expect(find(m.deps, 'idna')).toMatchObject({ version: '2.7', direct: false, via: ['requests'] });
    expect(find(m.deps, 'django')).toMatchObject({ version: '3.2.0', direct: true });
  });

  it('requirements-dev.txt is dev', () => {
    expect(find(depsOf('python', 'requirements-dev.txt'), 'pytest')).toMatchObject({ dev: true });
  });

  it('poetry.lock with pyproject groups', () => {
    const deps = depsOf('poetry', 'poetry.lock');
    expect(find(deps, 'jinja2')).toMatchObject({ version: '2.10', direct: true, dev: false, tool: 'poetry' });
    expect(find(deps, 'markupsafe')).toMatchObject({ direct: false, via: ['jinja2'] });
    expect(find(deps, 'black')).toMatchObject({ direct: true, dev: true });
  });

  it('uv.lock skips the project itself', () => {
    const deps = depsOf('uv', 'uv.lock');
    expect(deps.map((d) => d.name).sort()).toEqual(['aiohttp', 'pytest', 'yarl']);
    expect(find(deps, 'aiohttp')).toMatchObject({ version: '3.8.0', direct: true, dev: false });
    expect(find(deps, 'pytest')).toMatchObject({ direct: true, dev: true });
    expect(find(deps, 'yarl')).toMatchObject({ direct: false, via: ['aiohttp'] });
  });
});

describe('other ecosystems', () => {
  it('go.mod: direct/indirect, strips v, drops local replaces', () => {
    const deps = depsOf('go', 'go.mod');
    expect(deps.map((d) => d.name)).toEqual(['github.com/gin-gonic/gin', 'golang.org/x/text', 'golang.org/x/net']);
    expect(find(deps, 'github.com/gin-gonic/gin')).toMatchObject({ version: '1.6.0', direct: true });
    expect(find(deps, 'golang.org/x/text')).toMatchObject({ version: '0.3.0', direct: false });
  });

  it('Cargo.lock', () => {
    const deps = depsOf('rust', 'Cargo.lock');
    expect(deps.map((d) => d.name).sort()).toEqual(['chrono', 'smallvec', 'time']);
    expect(find(deps, 'time')).toMatchObject({ version: '0.1.43', direct: false, via: ['chrono'] });
    expect(find(deps, 'smallvec')).toMatchObject({ direct: true });
  });

  it('Gemfile.lock strips platform suffixes', () => {
    const deps = depsOf('ruby', 'Gemfile.lock');
    expect(find(deps, 'nokogiri')).toMatchObject({ version: '1.10.0', direct: true });
    expect(find(deps, 'rack')).toMatchObject({ version: '2.0.6', direct: true });
    expect(find(deps, 'mini_portile2')).toMatchObject({ direct: false, via: ['nokogiri'] });
  });

  it('composer.lock skips platform and branch versions', () => {
    const deps = depsOf('php', 'composer.lock');
    expect(deps.map((d) => d.name).sort()).toEqual(['guzzlehttp/guzzle', 'guzzlehttp/psr7', 'phpunit/phpunit']);
    expect(find(deps, 'guzzlehttp/psr7')).toMatchObject({ direct: false, via: ['guzzlehttp/guzzle'] });
    expect(find(deps, 'phpunit/phpunit')).toMatchObject({ dev: true, direct: true });
  });

  it('NuGet lock (and csproj is skipped next to it)', () => {
    const deps = depsOf('dotnet', 'packages.lock.json');
    expect(deps.map((d) => `${d.name}@${d.version}:${d.direct}`)).toEqual(['Newtonsoft.Json@12.0.1:true', 'System.Text.Encodings.Web@4.5.0:false']);
    expect(parseFile(join(FX, 'dotnet', 'App.csproj'), join(FX, 'dotnet'))).toBeUndefined();
  });

  it('pom.xml resolves properties, ignores comments, counts unversioned', () => {
    const m = parseFile(join(FX, 'java', 'pom.xml'), join(FX, 'java'))!;
    expect(m.deps.map((d) => `${d.name}@${d.version}`)).toEqual(['org.apache.logging.log4j:log4j-core@2.14.1', 'junit:junit@4.12']);
    expect(find(m.deps, 'junit:junit')).toMatchObject({ dev: true });
    expect(m.unpinned).toBe(1);
  });
});

describe('detection', () => {
  it('finds every fixture file and parses the whole tree', () => {
    const files = findDependencyFiles(FX).map((f) => f.slice(FX.length + 1).replace(/\\/g, '/')).sort();
    expect(files).toContain('npm/package-lock.json');
    expect(files).toContain('go/go.mod');
    expect(files).not.toContain('uv/pyproject.toml');
    const { manifests, errors } = parseProject(FX);
    expect(errors).toEqual([]);
    expect(new Set(manifests.map((m) => m.ecosystem))).toEqual(new Set(['npm', 'PyPI', 'Go', 'crates.io', 'RubyGems', 'Packagist', 'NuGet', 'Maven']));
  });
});
