import { run, bench, summary, barplot, do_not_optimize } from 'mitata';
import { generateKeyFingerprint, generatePairwiseFingerprint } from '..';
import { generateKeyFingerprint as libdave_generateKeyFingerprint, generatePairwiseFingerprint as libdave_generatePairwiseFingerprint } from './libdave/libdave';

// generateKeyFingerprint
barplot(() => {
  summary(() => {
    bench('@snazzah/davey/generateKeyFingerprint',
      () => do_not_optimize(generateKeyFingerprint(0, Buffer.alloc(33), '1234'))
    ).gc('inner');
    bench('libdave/generateKeyFingerprint',
      () => do_not_optimize(libdave_generateKeyFingerprint(0, new Uint8Array(33), '1234'))
    ).gc('inner');
  });
});

// generatePairwiseFingerprint
barplot(() => {
  summary(() => {
    bench('@snazzah/davey/generatePairwiseFingerprint',
      async () => do_not_optimize(
        await generatePairwiseFingerprint(0, Buffer.alloc(33), '1234', Buffer.alloc(65), '5678')
      )
    ).gc('inner');
    bench('libdave/generatePairwiseFingerprint',
      async () => do_not_optimize(
        await libdave_generatePairwiseFingerprint(0, new Uint8Array(33), '1234', new Uint8Array(65), '5678')
      )
    ).gc('inner');
  });
});

await run();