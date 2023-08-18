import base64

args = getScriptArgs()
arg = base64.b64decode(args[0] + b"==")
addrs = findBytes(None, arg, 1)

print("=====BIGCHEESE_START=====")

if len(addrs) == 0:
    print(":x: No matches found.")
else:
    print(":white_check_mark: Signature matches:")
    for addr in addrs:
        print(" - `0x" + addr.toString("") + "`")

print("=====BIGCHEESE_END=====")
