import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { transform } from 'esbuild';
import JavaScriptObfuscator from 'javascript-obfuscator';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(scriptDirectory, '..');
const sourceDirectory = path.join(projectRoot, 'public');
const outputDirectory = path.join(projectRoot, 'dist', 'public');

const applicationScripts = [
  'assets/app.js',
  'assets/communications.js',
  'assets/version.js',
  'assets/status.js',
  'assets/setup.js',
  'assets/utils.js'
];

const obfuscatorOptions = {
  compact: true,
  controlFlowFlattening: false,
  deadCodeInjection: false,
  debugProtection: false,
  disableConsoleOutput: false,
  identifierNamesGenerator: 'hexadecimal',
  numbersToExpressions: false,
  renameGlobals: false,
  renameProperties: false,
  seed: 20260714,
  selfDefending: false,
  simplify: true,
  stringArray: false,
  transformObjectKeys: false,
  unicodeEscapeSequence: false
};

async function buildApplicationScript(relativePath) {
  const sourcePath = path.join(sourceDirectory, relativePath);
  const outputPath = path.join(outputDirectory, relativePath);
  const source = await fs.readFile(sourcePath, 'utf8');

  // Keep top-level names intact because utils.js is shared through classic
  // browser scripts. The obfuscator may still rename local identifiers.
  const minified = await transform(source, {
    charset: 'utf8',
    legalComments: 'none',
    loader: 'js',
    minifyIdentifiers: false,
    minifySyntax: true,
    minifyWhitespace: true,
    sourcefile: relativePath,
    sourcemap: false,
    target: 'es2020'
  });

  const obfuscated = JavaScriptObfuscator.obfuscate(
    minified.code,
    obfuscatorOptions
  ).getObfuscatedCode();

  await fs.writeFile(outputPath, `${obfuscated}\n`, 'utf8');

  const sourceSize = Buffer.byteLength(source);
  const outputSize = Buffer.byteLength(obfuscated);
  const reduction = sourceSize === 0
    ? 0
    : Math.round((1 - outputSize / sourceSize) * 100);

  console.log(
    `[build:public] ${relativePath}: ${sourceSize} -> ${outputSize} bytes (${reduction}% reduction)`
  );
}

async function main() {
  await fs.rm(outputDirectory, { recursive: true, force: true });
  await fs.mkdir(path.dirname(outputDirectory), { recursive: true });
  await fs.cp(sourceDirectory, outputDirectory, { recursive: true });

  for (const relativePath of applicationScripts) {
    await buildApplicationScript(relativePath);
  }

  console.log(`[build:public] Production assets written to ${outputDirectory}`);
}

main().catch((error) => {
  console.error('[build:public] Build failed:', error);
  process.exitCode = 1;
});
