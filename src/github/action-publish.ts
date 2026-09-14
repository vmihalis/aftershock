import { pathToFileURL } from "node:url";
import { DemoController } from "../api/demo-controller.js";
import type { AftershockView } from "../api/view.js";
import {
  githubTokenClient,
  publishAssessment,
  type PublishedAssessment,
} from "./publisher.js";

export const AUTHORIZED_DEMO_REPOSITORY = "vmihalis/aftershock-apm-fixture";

type FetchLike = typeof fetch;

export type ActionPublishResult = Readonly<{
  frame: number;
  state: AftershockView["assessment"]["state"];
  repository: string;
  headSha: string;
  publication: PublishedAssessment;
}>;

function parseFrame(raw: string | undefined): number {
  if (raw === undefined || !/^[1-6]$/.test(raw)) {
    throw new TypeError("Aftershock frame must be one integer from 1 through 6");
  }
  return Number(raw);
}

function frameFromArguments(arguments_: readonly string[]): string | undefined {
  let selected: string | undefined;
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--frame") {
      if (selected !== undefined || index + 1 >= arguments_.length) {
        throw new TypeError("Use --frame exactly once with a value from 1 through 6");
      }
      selected = arguments_[index + 1];
      index += 1;
      continue;
    }
    if (argument.startsWith("--frame=")) {
      if (selected !== undefined) throw new TypeError("Use --frame exactly once");
      selected = argument.slice("--frame=".length);
      continue;
    }
    throw new TypeError(`Unsupported action publisher argument: ${argument}`);
  }
  return selected;
}

export function selectDemoFrame(frame: number): AftershockView {
  if (!Number.isInteger(frame) || frame < 1 || frame > 6) {
    throw new TypeError("Aftershock frame must be one integer from 1 through 6");
  }
  const controller = new DemoController();
  for (let index = 1; index < frame; index += 1) controller.advance();
  const view = controller.view();
  if (view.meta.frame !== frame || !/^[0-9a-f]{40}$/.test(view.repository.headSha)) {
    throw new Error("Selected demo frame does not contain a publishable repository revision");
  }
  return view;
}

export async function publishActionFrame(
  environment: NodeJS.ProcessEnv = process.env,
  arguments_: readonly string[] = process.argv.slice(2),
  fetchImpl: FetchLike = fetch,
): Promise<ActionPublishResult> {
  const repository = environment.GITHUB_REPOSITORY;
  if (repository !== AUTHORIZED_DEMO_REPOSITORY) {
    throw new Error(`Refusing publication outside ${AUTHORIZED_DEMO_REPOSITORY}`);
  }
  const token = environment.GITHUB_TOKEN;
  if (!token || token.trim().length === 0) {
    throw new Error("GITHUB_TOKEN is required for GitHub Actions publication");
  }
  const frame = parseFrame(frameFromArguments(arguments_) ?? environment.AFTERSHOCK_FRAME);
  const view = selectDemoFrame(frame);
  if (view.repository.fullName !== repository) {
    throw new Error("Selected demo frame does not match the authorized Actions repository");
  }

  const publication = await publishAssessment(githubTokenClient(token, fetchImpl), view);
  return {
    frame,
    state: view.assessment.state,
    repository,
    headSha: view.repository.headSha,
    publication,
  };
}

async function main(): Promise<void> {
  const result = await publishActionFrame();
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(invokedPath).href) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Unknown action publisher failure";
    process.stderr.write(`Aftershock publication failed: ${message}\n`);
    process.exitCode = 1;
  });
}
