const fs = require("fs");
const { execSync } = require("child_process");

module.exports = {
  manifest: {
    name: "info",
    description: "Returns info about the bot"
  },
  exec: async (interaction) => {
    const bigCheeseHash = execSync("git rev-parse --short HEAD")
      .toString()
      .trim();

    const csHash = execSync("git rev-parse --short HEAD", {
      cwd: "./FFXIVClientStructs"
    })
      .toString()
      .trim();

    const gameVer = process.env["BIGCHEESE_GAMEVER"] || "unknown";

    const ghidraVer = fs
      .readFileSync("./ghidra/Ghidra/application.properties", "utf8")
      .trim()
      .split("\n")
      .find((x) => x.startsWith("application.version="))
      .replace("application.version=", "");

    await interaction.createMessage({
      embeds: [
        {
          title: `The Big Cheese`,
          description: `Powered by Ghidra. [Source available on GitHub](https://github.com/NotNite/bigcheese).`,
          color: 0x00ffff,
          fields: [
            {
              name: `Bot version`,
              value: `[${bigCheeseHash}](https://github.com/NotNite/bigcheese/commit/${bigCheeseHash})`,
              inline: true
            },
            {
              name: `ClientStructs version`,
              value: `[${csHash}](https://github.com/aers/FFXIVClientStructs/commit/${csHash})`,
              inline: true
            },
            {
              name: `Game version`,
              value: gameVer,
              inline: true
            },
            {
              name: `Ghidra version`,
              value: ghidraVer,
              inline: true
            }
          ]
        }
      ]
    });
  }
};
