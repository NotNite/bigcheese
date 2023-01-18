const fs = require("fs");
const config = JSON.parse(fs.readFileSync("./config.json", "utf8"));
const { spawn } = require("child_process");

function spawnGhidra(script, args, doSafetyCheck = true) {
  return new Promise((resolve, reject) => {
    if (doSafetyCheck) {
      const safetyCheck = /^[0-9a-fA-F]+$/.test(args);
      if (!safetyCheck) {
        reject("Invalid args");
        return;
      }
    }

    const ghidra = spawn(config.ghidraExecutable, [
      "ghidra-project",
      "bigcheese",
      "-process",
      "ffxiv_dx11.exe",
      "-noanalysis",
      "-readonly",
      "-postScript",
      config.scriptDir + "/" + script,
      args
    ]);

    let stdout = "";
    ghidra.stdout.on("data", (data) => {
      process.stdout.write(data.toString());
      stdout += data.toString();
    });

    ghidra.stderr.on("data", (data) => {
      process.stderr.write(data.toString());
    });

    // =====BIGCHEESE_START=====
    // (snip)
    // =====BIGCHEESE_END=====
    const regex =
      /=====BIGCHEESE_START=====\n([\s\S]+?)\n=====BIGCHEESE_END=====/gm;
    ghidra.on("close", (code) => {
      const match = regex.exec(stdout);
      if (match == null) {
        reject("wuh oh");
        return;
      }
      resolve(match[1].trim());
    });
  });
}

function parseOffset(str) {
  let ret = str.trim();

  if (ret.startsWith("ffxiv_dx11.exe+")) ret.replace("ffxiv_dx11.exe+", "");
  if (ret.startsWith("0x")) ret.replace("0x", "");
  if (ret.startsWith("sub_")) ret.replace("sub_", "");
  if (ret.startsWith("FUN_")) ret.replace("FUN_", "");

  // parse as hex
  let parsed = parseInt(ret, 16);

  if (parsed < 0x140000000) parsed += 0x140000000;

  // return as hex
  const toStr = parsed.toString(16);

  return isNaN(parsed) ? null : toStr;
}

async function sendToHast(input) {
  const req = await fetch("https://haste.soulja-boy-told.me/documents", {
    method: "POST",
    body: input
  });

  const json = await req.json();
  return `https://haste.soulja-boy-told.me/raw/${json.key}`;
}

function parseSig(sig) {
  const sigParts = sig.split(" ");

  for (const part of sigParts) {
    if (part.length > 2) return null;

    if (part === "??" || part === "?") continue;

    const parsed = parseInt(part, 16);
    if (isNaN(parsed)) return null;
    if (parsed > 0xff) return null;
    if (parsed < 0x00) return null;
  }

  const the = sigParts
    .map((x) => {
      if (x === "??" || x === "?") return ".";
      return `\\x${x}`;
    })
    .join("");

  return Buffer.from(the).toString("base64");
}

module.exports = {
  spawnGhidra,
  parseOffset,
  sendToHast,
  parseSig
};
