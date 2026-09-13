import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

export const pythonPackageReference = "python/python@=3.13.18";

// This is the SDK cache entry produced for the pinned package reference above.
// Loading its WEBC bytes directly avoids a registry lookup in later processes.
const cachedPackageEntry =
  "cache-v1/packages/0464f16f1ad0ce4d1ab4266b057b62accd5b4123995a08103897699aefc92a54.bin";

export async function selectPythonPackage(cacheDirectory) {
  const artifactPath = resolve(cacheDirectory, cachedPackageEntry);
  try {
    return {
      source: await readFile(artifactPath),
      acquisition: "cached_webc_bytes",
      artifactPath,
    };
  } catch (error) {
    if (error === null || typeof error !== "object" || error.code !== "ENOENT") {
      throw error;
    }
    return {
      source: pythonPackageReference,
      acquisition: "registry_reference",
      artifactPath: null,
    };
  }
}
