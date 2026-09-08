import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const root = process.cwd();
const sourceDirs = ['app'];
const extensions = new Set(['.ts', '.tsx']);
const errors = [];

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) walk(full);
    else if (extensions.has(extname(full))) checkFile(full);
  }
}

function checkFile(file) {
  const source = readFileSync(file, 'utf8');
  const relative = file.replace(`${root}/`, '');

  if (/\bconsole\.(log|debug|info|warn|error)\s*\(/.test(source)) {
    errors.push(`${relative}: console statements are not allowed in committed frontend code.`);
  }

  if (/<img\b/i.test(source)) {
    errors.push(`${relative}: use Next/Image or an accessible alternative instead of a raw <img>.`);
  }

  const buttonBlocks = source.match(/<button\b[\s\S]*?<\/button>/g) ?? [];
  for (const block of buttonBlocks) {
    const visibleText = block
      .replace(/<[^>]+>/g, ' ')
      .replace(/\{[^}]*\}/g, ' ')
      .replace(/&[a-z]+;/gi, ' ')
      .replace(/\s+/g, ' ')
      .trim();
    const hasText = visibleText.length > 0;
    const hasAriaLabel = /\baria-label\s*=/.test(block);
    const hasTitle = /\btitle\s*=/.test(block);
    if (!hasText && !hasAriaLabel && !hasTitle) {
      errors.push(`${relative}: icon-only button needs an aria-label or title.`);
    }
  }
}

for (const dir of sourceDirs) {
  walk(join(root, dir));
}

if (errors.length) {
  console.error(`Lint failed with ${errors.length} issue(s):`);
  for (const error of errors) console.error(`- ${error}`);
  process.exit(1);
}

console.log('Lint passed: accessibility and frontend hygiene checks completed.');
