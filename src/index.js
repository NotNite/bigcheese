const Eris = require("eris");
const fs = require("fs");

const config = JSON.parse(fs.readFileSync("./config.json", "utf8"));

const bot = new Eris.Client("Bot " + config.discordToken, {
  restMode: true,
  intents: Eris.Constants.Intents.allNonPrivileged
});

const commands = fs
  .readdirSync("./src/commands")
  .map((file) => require(`./commands/${file}`));

bot.on("ready", async () => {
  const cmds = commands.map((x) => x.manifest);

  await bot.bulkEditGuildCommands(config.discordGuild, cmds);
  await bot.bulkEditCommands(cmds);

  console.log("ready 2 rumble");
});

bot.on("interactionCreate", async (interaction) => {
  if (interaction.type !== Eris.Constants.InteractionTypes.APPLICATION_COMMAND)
    return;

  const command = commands.find(
    (x) => x.manifest.name === interaction.data.name
  );

  console.log(
    `${interaction.user.id} - ${interaction.data.name} - ${JSON.stringify(
      interaction.data
    )}`
  );
  if (command != null) {
    try {
      await command.exec(interaction);
    } catch (e) {
      console.error(e);

      await interaction.createFollowup({
        content: ":x: An error occurred - Tell Jules!",
        flags: 64
      });
    }
  }
});

bot.connect();
