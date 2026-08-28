/**
 * Writes a file without following a symlink at the destination.
 *
 * `fs.writeFile` follows symlinks, so a repository that ships
 * `sentinel-report.md` as a link to somewhere else had that target overwritten
 * when a report was written into the scanned tree. Renaming onto the
 * destination replaces the link itself instead of writing through it, which is
 * what `writeBaseline` has always done and what the report writers did not.
 */

import * as fsp from "node:fs/promises";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

export async function writeFileNoFollow(filePath: string, contents: string): Promise<void> {
  const resolved = path.resolve(filePath);
  const directory = path.dirname(resolved);
  const temporary = path.join(
    directory,
    `.${path.basename(resolved)}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`
  );

  await fsp.mkdir(directory, { recursive: true });

  try {
    // "wx" refuses an existing path, so a temp name cannot collide with a
    // concurrent write or be pre-planted by the scanned repository.
    await fsp.writeFile(temporary, contents, { encoding: "utf-8", flag: "wx" });
    await fsp.rename(temporary, resolved);
  } catch (error) {
    await fsp.rm(temporary, { force: true });
    throw error;
  }
}
