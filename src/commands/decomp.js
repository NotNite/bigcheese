const Eris = require("eris");
const util = require("../util");
const { enqueue } = require("../taskQueue");

module.exports = {
  manifest: {
    name: "decomp",
    description: "Decompile a function",
    options: [
      {
        name: "function",
        description: "The function to decompile",
        type: Eris.Constants.ApplicationCommandOptionTypes.STRING,
        required: true
      }
    ]
  },
  exec: async (interaction) => {
    const option = interaction.data.options[0].value;
    const offset = util.parseOffset(option);

    await interaction.acknowledge(64);

    if (offset !== null) {
      console.log("enqueing");
      enqueue(
        async () => {
          const gh = await util.spawnGhidra("decompile.py", offset);

          const codeblock = "```c\n" + gh + "\n```";
          if (codeblock.length > 2000) {
            const haste = await util.sendToHast(gh);
            await interaction.createFollowup({
              content: `:white_check_mark: Output too long for Discord: <${haste}>`,
              flags: 64
            });
          } else {
            await interaction.createFollowup({
              content: codeblock,
              flags: 64
            });
          }
        },
        async () => {
          await interaction.createFollowup({
            content: ":x: Decompilation failed - Tell Jules!",
            flags: 64
          });
        }
      );
    }
  }
};
