const { Constants } = require("@projectdysnomia/dysnomia");
const util = require("../util");
const { enqueue } = require("../taskQueue");

module.exports = {
  manifest: {
    name: "sigmaker",
    description: "Create a signature",
    options: [
      {
        name: "address",
        description: "The address to sig",
        type: Constants.ApplicationCommandOptionTypes.STRING,
        required: true
      }
    ]
  },
  exec: async (interaction) => {
    const option = interaction.data.options[0].value;
    const offset = util.parseOffset(option);

    await interaction.acknowledge(64);

    if (offset !== null) {
      console.log("enqueing sigmaker.py");
      enqueue(
        async () => {
          const gh = await util.spawnGhidra("sigmaker.py", offset);

          await interaction.createFollowup({
            content: gh,
            flags: 64
          });
        },
        async () => {
          await interaction.createFollowup({
            content: ":x: Signature creation failed - Tell Jules!",
            flags: 64
          });
        }
      );
    } else {
      await interaction.createFollowup({
        content: ":x: Couldn't parse offset.",
        flags: 64
      });
    }
  }
};
