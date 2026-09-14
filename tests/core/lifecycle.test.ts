import assert from "node:assert/strict";
import test from "node:test";
import {
  appendAssessment,
  buildDeterministicDemoSequence,
  createStaleAssessment,
  sha256Text,
  supersededBy,
} from "../../src/core/index.js";

test("deterministic replay covers match, observation, remediation, and stale current head", () => {
  const first = buildDeterministicDemoSequence();
  const second = buildDeterministicDemoSequence();
  assert.deepEqual(
    first.assessments.map((assessment) => assessment.state),
    ["POTENTIALLY_AFFECTED", "OBSERVED_BY_CHECK", "REMEDIATION_RETESTED", "EVIDENCE_STALE_FOR_CURRENT_HEAD"],
  );
  assert.deepEqual(first, second);
  assert.deepEqual(
    first.events.map((event) => event.sequence),
    [1, 2, 3, 4],
  );
});

test("records remain immutable and supersession is an append-only chain", () => {
  const sequence = buildDeterministicDemoSequence();
  const [potential, observed, remediated, stale] = sequence.assessments;
  assert.ok(potential && observed && remediated && stale);
  assert.equal(observed.supersedes, potential.id);
  assert.equal(remediated.supersedes, observed.id);
  assert.equal(stale.supersedes, remediated.id);
  assert.equal(supersededBy(sequence.assessments, potential.id), observed.id);
  assert.equal(Object.isFrozen(potential), true);
  assert.equal(Object.isFrozen(observed.observations), true);
  assert.deepEqual(stale.evidence.staleAxes, ["REPOSITORY_SHA"]);
  assert.equal(stale.observations.length, 0, "stale record must not inherit old run evidence");
});

test("a superseded record cannot be rewritten or forked", () => {
  const sequence = buildDeterministicDemoSequence();
  const [potential, observed] = sequence.assessments;
  assert.ok(potential && observed);
  assert.throws(() => appendAssessment([potential, observed], observed), /already exists/u);

  const fork = { ...observed, id: `assessment:${"f".repeat(24)}` as typeof observed.id };
  assert.throws(() => appendAssessment([potential, observed], fork), /already has a superseding record/u);
});

test("staleness requires an actual immutable-axis change", () => {
  const sequence = buildDeterministicDemoSequence();
  const remediated = sequence.assessments[2]!;
  assert.throws(
    () =>
      createStaleAssessment({
        previous: remediated,
        repository: remediated.repository,
        source: remediated.source,
        capsule: remediated.capsule,
        applicability: remediated.evidence.applicability,
        createdAt: sequence.assessments[3]!.createdAt,
      }),
    /still current/u,
  );
});

test("source and capsule changes independently withdraw evidence without a repository change", () => {
  const sequence = buildDeterministicDemoSequence();
  const previous = sequence.assessments[2]!;
  const unchanged = {
    previous,
    repository: previous.repository,
    source: previous.source,
    capsule: previous.capsule,
    applicability: previous.evidence.applicability,
    createdAt: sequence.assessments[3]!.createdAt,
  };
  const cases = [
    { axis: "SOURCE_REVISION", input: { ...unchanged, source: { ...previous.source, revision: "reviewed-source-r2" } } },
    { axis: "CAPSULE_REVISION", input: { ...unchanged, capsule: { ...previous.capsule, revision: "r2" } } },
    { axis: "CAPSULE_DIGEST", input: { ...unchanged, capsule: { ...previous.capsule, digest: sha256Text("changed contract") } } },
  ];
  for (const { axis, input } of cases) {
    const stale = createStaleAssessment(input);
    assert.equal(stale.state, "EVIDENCE_STALE_FOR_CURRENT_HEAD");
    assert.equal(stale.repository.headSha, previous.repository.headSha);
    assert.deepEqual(stale.evidence.staleAxes, [axis]);
    assert.equal(stale.observations.length, 0);
    assert.equal(stale.supersedes, previous.id);
    assert.notEqual(stale.id, previous.id);
  }
  assert.equal(previous.state, "REMEDIATION_RETESTED");
  assert.equal(previous.observations.length, 3, "historical evidence is retained in its original record");
});
