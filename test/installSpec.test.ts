import { describe, expect, it } from 'vitest';
import { parseInstallCommand, splitCommands } from '../src/installSpec.js';

const intents = (cmd: string) => parseInstallCommand(cmd).intents.map((i) => `${i.ecosystem}:${i.name}:${i.kind}:${i.version ?? ''}`);

describe('splitCommands', () => {
  it('splits on && || ; | newlines but not inside quotes', () => {
    expect(splitCommands('cd app && npm i x; echo "a && b" || true')).toEqual(['cd app', 'npm i x', 'echo "a && b"', 'true']);
  });
});

describe('parseInstallCommand', () => {
  it('npm family', () => {
    expect(intents('npm install lodash@4.17.15 -D @types/node@^20 express')).toEqual([
      'npm:lodash:exact:4.17.15',
      'npm:@types/node:range:^20',
      'npm:express:latest:',
    ]);
    expect(intents('pnpm add -w react@next')).toEqual(['npm:react:range:next']);
    expect(intents('yarn add left-pad@latest')).toEqual(['npm:left-pad:latest:']);
    expect(intents('npm i ./local ../x.tgz user/repo git+https://x file:../y')).toEqual([]);
    expect(intents('npm install')).toEqual([]);
    expect(intents('npm run build')).toEqual([]);
    expect(intents('cd web && NODE_ENV=dev npm i axios@0.21.0')).toEqual(['npm:axios:exact:0.21.0']);
  });

  it('python', () => {
    expect(intents('pip install requests==2.19.0 "django[argon2]>=3" flask~=2.0 ./pkg')).toEqual([
      'PyPI:requests:exact:2.19.0',
      'PyPI:django:latest:',
    ]);
    expect(intents('python -m pip install -U urllib3')).toEqual(['PyPI:urllib3:latest:']);
    expect(intents('uv add "jinja2==2.10" --dev')).toEqual(['PyPI:jinja2:exact:2.10']);
    expect(intents('poetry add aiohttp@3.8.0 --group dev')).toEqual(['PyPI:aiohttp:exact:3.8.0']);
    expect(parseInstallCommand('pip install -r requirements.txt -rdev.txt').requirementFiles).toEqual(['requirements.txt', 'dev.txt']);
  });

  it('cargo, go, gem, composer, dotnet', () => {
    expect(intents('cargo add time@0.1.43 serde --features derive')).toEqual(['crates.io:time:exact:0.1.43', 'crates.io:serde:latest:']);
    expect(intents('cargo add foo --git https://x')).toEqual([]);
    expect(intents('go get golang.org/x/text@v0.3.0 github.com/gin-gonic/gin@latest')).toEqual(['Go:golang.org/x/text:exact:0.3.0', 'Go:github.com/gin-gonic/gin:latest:']);
    expect(intents('gem install rack -v 2.0.6')).toEqual(['RubyGems:rack:exact:2.0.6']);
    expect(intents('bundle add nokogiri')).toEqual(['RubyGems:nokogiri:latest:']);
    expect(intents('composer require guzzlehttp/guzzle:7.4.0 monolog/monolog')).toEqual(['Packagist:guzzlehttp/guzzle:exact:7.4.0', 'Packagist:monolog/monolog:latest:']);
    expect(intents('dotnet add src/App.csproj package Newtonsoft.Json --version 12.0.1')).toEqual(['NuGet:Newtonsoft.Json:exact:12.0.1']);
  });
});
