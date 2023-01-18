# bigcheese

ffxiv reverse engineering discord bot

## setup

- clone and init submodules
- download ghidra into `ghidra` and make an empty `ghidra-project` folder
- setup the project with clientstructs:

```sh
# Install dependencies (MUST use python 2)
python2 -m pip install \
-t "D:\code\js\bigcheese\ghidra\Ghidra\Features\Python\data\jython-2.7.3\Lib\site-packages" \
pyyaml==5.4.1 anytree

# Decompile & rename
./ghidra/support/analyzeHeadless ghidra-project bigcheese \
-import "D:/code/js/bigcheese/bins/ffxiv_dx11.exe" \
-postScript "D:/code/js/bigcheese/FFXIVClientStructs/ida/ffxiv_idarename.py"
```

- setup a config.json:

```json
{
  "ghidraExecutable": "D:/code/js/bigcheese/ghidra/support/analyzeHeadless.bat",
  "scriptDir": "D:/code/js/bigcheese/scripts",
  "discordToken": "no",
  "discordGuild": "no"
}
```

- `pnpm i`
- `node src/index.js`
- done
