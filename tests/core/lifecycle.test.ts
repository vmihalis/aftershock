import assert from "node:assert/strict";
import test from "node:test";
import {
  appendAssessment,
  buildDeterministicDemoSequence,
  createStaleAssessment,
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
