import { DemoController } from "./api/demo-controller.js";

const controller = new DemoController();
const delayFlag = process.argv.find((value) => value.startsWith("--delay="));
const delayMs = delayFlag ? Number.parseInt(delayFlag.split("=")[1] ?? "0", 10) : 0;

for (let frame = 0; frame < controller.view().meta.frameCount; frame += 1) {
  const view = frame === 0 ? controller.view() : controller.advance();
  console.log(JSON.stringify({
    frame: view.meta.frame,
    state: view.assessment.state,
    sha: view.repository.headSha,
    summary: view.assessment.summary,
    event: view.events.at(-1),
    matrix: view.matrix,
  }));
  if (delayMs > 0 && frame < view.meta.frameCount - 1) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
}
