const Eris = require("eris");
const util = require("../util");
const { enqueue } = require("../taskQueue");

module.exports = {
  manifest: {
    name: "sigtest",
    description: "Test a signature",
    options: [
      {
        name: "signature",
        description: "The signature to test",
        type: Eris.Constants.ApplicationCommandOptionTypes.STRING,
        required: true
      }
    ]
  },
  exec: async (interaction) => {
    const option = interaction.data.options[0].value;
    const sig = util.parseSig(option);

    await interaction.acknowledge(64);

    if (sig !== null) {
      console.log("enqueing sigtest.py");
      enqueue(
        async () => {
          const gh = await util.spawnGhidra("sigtest.py", sig, false);

          await interaction.createFollowup({
            content: gh,
            flags: 64
          });
        },
        async () => {
          await interaction.createFollowup({
            content: ":x: Signature test failed - Tell Jules!",
            flags: 64
          });
        }
      );
    } else {
      await interaction.createFollowup({
        content:
          ":x: Couldn't parse signature. If this works in your code, tell Jules!",
        flags: 64
      });
    }
  }
};
