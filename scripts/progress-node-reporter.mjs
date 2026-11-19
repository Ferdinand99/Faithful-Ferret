// A reporter for `node --test` that only adds progress markers: one line
// `::progress:: k/N` for every test file that has finished, where N comes from
// FERRET_PROGRESS_TOTAL (the number of test files, set by progress_node_test in
// scripts/progress.sh). It is used next to the default reporter and prints
// nothing else.
//
//   FERRET_PROGRESS_TOTAL=3 node --test --test-reporter=spec \
//     --test-reporter=scripts/progress-node-reporter.mjs a.test.mjs b.test.mjs c.test.mjs

export default async function* progressReporter(source) {
  const total = Number.parseInt(process.env.FERRET_PROGRESS_TOTAL ?? '', 10);
  let finished = 0;
  for await (const event of source) {
    // One summary per test file; the last one, for the whole run, has no file.
    if (event.type === 'test:summary' && event.data.file && total > 0) {
      finished = Math.min(finished + 1, total);
      yield `::progress:: ${finished}/${total}\n`;
    }
  }
}
