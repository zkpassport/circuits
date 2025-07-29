#!/usr/bin/env tsx
/**
 * This script is used to automatically update the solidity fixtures by running the outer.test.ts for proof size 12
 */
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

// Define paths
const FIXTURES_DIR = path.join(__dirname, '../src/solidity/test/fixtures');
const OUTPUT_DIR = path.join(__dirname, '../output-fixtures');

console.log('Running outer.test.ts with DEBUG_OUTPUT=true...');

try {
  // Run the test with DEBUG_OUTPUT enabled
  execSync('cd src/ts && DEBUG_OUTPUT=true yarn test outer.test.ts --testNamePattern="12 subproofs"', {
    cwd: path.join(__dirname, '..'),
    encoding: 'utf8',
    stdio: 'inherit', // Show test output directly
  });

  console.log('\nTest completed. Copying fixtures...');

  // Check if output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    throw new Error(`Output directory not found: ${OUTPUT_DIR}`);
  }

  // Copy the fixture files
  const filesToCopy = [
    'all_subproofs_committed_inputs.hex',
    'all_subproofs_public_inputs.json',
    'all_subproofs_proof.hex'
  ];

  for (const fileName of filesToCopy) {
    const sourcePath = path.join(OUTPUT_DIR, fileName);
    const destPath = path.join(FIXTURES_DIR, fileName);
    
    if (!fs.existsSync(sourcePath)) {
      throw new Error(`Source file not found: ${sourcePath}`);
    }
    
    fs.copyFileSync(sourcePath, destPath);
    console.log(`Copied ${fileName}`);
  }

  // Clean up output directory
  fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
  
  console.log('\nFixture files updated successfully!');
  console.log(`Updated files in: ${FIXTURES_DIR}`);
  
} catch (error) {
  console.error('Error updating fixtures:', error);
  process.exit(1);
}