const { Client, Constants } = require("@projectdysnomia/dysnomia");
const fs = require("fs");

const config = JSON.parse(fs.readFileSync("./config.json", "utf8"));

const bot = new Client("Bot " + config.discordToken, {
  restMode: true,
  intents: Constants.Intents.allNonPrivileged
});

const commands = fs
  .readdirSync("./src/commands")
  .map((file) => require(`./commands/${file}`));

bot.on("ready", async () => {
  const cmds = commands.map((x) => x.manifest);

  if (process.env["NODE_ENV"] === "production") {
    console.log("running in production mode");
    await bot.bulkEditCommands(cmds);
  } else {
    console.log("running in dev mode");
    await bot.bulkEditGuildCommands(config.discordGuild, cmds);
  }

  console.log("ready 2 rumble");
});

bot.on("interactionCreate", async (interaction) => {
  if (interaction.type !== Constants.InteractionTypes.APPLICATION_COMMAND)
    return;

  const command = commands.find(
    (x) => x.manifest.name === interaction.data.name
  );

  const id = interaction.user ? interaction.user?.id : interaction.member?.id;

  console.log(
    `${id} - ${interaction.data.name} - ${JSON.stringify(interaction.data)}`
  );
  if (command != null) {
    try {
      await command.exec(interaction);
    } catch (e) {
      console.error(e);

      await interaction.createMessage({
        content: ":x: An error occurred - Tell Jules!",
        flags: 64
      });
    }
  }
});

bot.connect();
