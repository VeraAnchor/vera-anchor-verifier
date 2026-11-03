#!/usr/bin/env node
import { runVerifierCliV1 } from "./cli/commandV1.js";

void runVerifierCliV1(process.argv.slice(2), (line) => process.stdout.write(`${line}\n`))
  .then((code) => { process.exitCode = code; });
