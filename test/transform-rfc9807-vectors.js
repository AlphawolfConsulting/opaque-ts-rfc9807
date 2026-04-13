#!/usr/bin/env node


import fs from 'fs';
import path from 'path';
import { program } from 'commander';

program
  .option('-i, --input <file>', 'Input JSON file', 'test/extractedrfc9807TestVectors.json')
  .option('-o, --output <dir>', 'Output directory or file', 'test/rfc9807-vectors-for-tests.json')
  .option('-s, --split', 'Write each vector to a separate file')
  .option('-a, --array', 'Write all vectors as a single array (default)')
  .parse(process.argv);

const opts = program.opts();

const input = JSON.parse(fs.readFileSync(opts.input, 'utf8'));
const outputVectors = [];

function getPrefix(section) {
  return section.split('.').slice(0, 3).join('.');
}

for (const [section, entry] of Object.entries(input)) {
  if (entry.label === 'OutputValues') {
    const prefix = getPrefix(section);
    const config = input[`${prefix}.1`] && input[`${prefix}.1`].fields;
    const inputValues = input[`${prefix}.2`] && input[`${prefix}.2`].fields;
    const intermediate = input[`${prefix}.3`] && input[`${prefix}.3`].fields;
    const outputValues = entry.fields;
    outputVectors.push({
      section: prefix,
      config,
      inputs: inputValues,
      intermediates: intermediate,
      outputs: outputValues,
    });
  }
}

if (opts.split) {
  // Write each vector to a separate file in the output directory
  if (!fs.existsSync(opts.output)) {
    fs.mkdirSync(opts.output, { recursive: true });
  }
  outputVectors.forEach((vector, idx) => {
    const fileName = `${vector.section.replace(/\./g, '-')}.json`;
    fs.writeFileSync(path.join(opts.output, fileName), JSON.stringify(vector, null, 2));
  });
  console.log(`Wrote ${outputVectors.length} vector files to ${opts.output}`);
} else {
  // Write all vectors as an array to the output file
  fs.writeFileSync(opts.output, JSON.stringify(outputVectors, null, 2));
  console.log(`Wrote array of ${outputVectors.length} vectors to ${opts.output}`);
}
