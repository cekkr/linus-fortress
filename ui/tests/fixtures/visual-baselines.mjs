import fs from "node:fs";

const renderer = `${process.platform}-${process.arch}`;

function readFixture(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    if (err.code === "ENOENT") return {};
    throw err;
  }
}

export function readVisualBaselines(file) {
  const fixture = readFixture(file);
  return fixture.platforms?.[renderer] || fixture;
}

export function writeVisualBaselines(file, observed) {
  const fixture = readFixture(file);
  fixture.platforms = { ...fixture.platforms, [renderer]: observed };
  fs.writeFileSync(file, `${JSON.stringify(fixture, null, 2)}\n`);
}
