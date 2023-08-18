import time
from ghidra.program.model.lang import OperandType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import Address

# https://gist.github.com/pohky/950768c433ba8bd51ab108c1b3153df8

max_references = 2000
min_signature_length = 3
max_signature_length = 64

reference_manager = currentProgram.getReferenceManager()
function_manager = currentProgram.getFunctionManager()
address_factory = currentProgram.getAddressFactory()
listing = currentProgram.getListing()

args = getScriptArgs()
offset = int(args[0], 16)
addr = address_factory.getDefaultAddressSpace().getAddress(offset)


def generate_signature(addr):
    fn = function_manager.getFunctionContaining(addr)
    if fn is None:
        return None

    ins = listing.getInstructionContaining(addr)
    if ins is None:
        return None

    pat = Pattern(max_signature_length + 15)
    body = fn.getBody()

    while body.contains(ins.getAddress()):
        pat.add(ins)
        if pat.size() >= min_signature_length:
            if pat.is_unique():
                return pat.trim()

        if pat.size() == 0 or pat.size() >= max_signature_length:
            break

        ins = ins.getNext()

    return None


class Pattern:
    def __init__(self, capacity):
        self.capacity = capacity
        self.bytes = []

    def add(self, insn):
        arr = self.mask_instruction(insn)
        self.bytes.extend(arr)

    def trim(self):
        for i in range(len(self.bytes) - 1, -1, -1):
            if self.bytes[i].is_wildcard:
                self.bytes.pop()
            else:
                break

        return self

    def size(self):
        return len(self.bytes)

    def is_unique(self):
        sig_str = ""
        for i in range(len(self.bytes)):
            byte = self.bytes[i]
            if byte.is_wildcard:
                sig_str += "."
            else:
                sig_str += "\\x" + str(byte)

        addrs = findBytes(None, sig_str, 2)
        return len(addrs) == 1

    def mask_instruction(self, insn):
        mask = bytearray(insn.getLength())
        proto = insn.getPrototype()
        bytes = insn.getBytes()
        list = []

        for op in range(insn.getNumOperands()):
            if self.should_mask_operand(insn, op):
                op_bytes = proto.getOperandValueMask(op).getBytes()
                for i in range(len(mask)):
                    mask[i] = mask[i] | op_bytes[i] & 0xFF

        for i in range(len(bytes)):
            b = PatternByte()

            if mask[i] == 255:
                b.is_wildcard = True
                b.value = 0
            else:
                b.is_wildcard = False

                signed = bytes[i]
                unsigned = signed & 0xFF
                b.value = unsigned

            list.append(b)

        return list

    def should_mask_operand(self, insn, op):
        optype = insn.getOperandType(op)
        return (
            (optype & OperandType.DYNAMIC) != 0
            or OperandType.isAddress(optype)
            or OperandType.isScalar(optype)
        )

    def __str__(self):
        return " ".join([str(b) for b in self.bytes])


class PatternByte:
    def __str__(self):
        if self.is_wildcard:
            return "??"

        return "{:02X}".format(self.value).upper()


refs = []
for ref in reference_manager.getReferencesTo(addr):
    addr2 = ref.getFromAddress()
    insn = getInstructionAt(addr2)
    if insn is None:
        continue

    type = ref.getReferenceType()
    if (type.isJump() or type.isData()) and insn.getLength() < 5:
        continue
    if type.isConditional():
        continue

    refs.append(addr2)
    if len(refs) >= max_references:
        break

if getInstructionAt(addr) is not None:
    refs.insert(0, addr)

block = currentProgram.getMemory().getBlock(".text")

text_section = bytearray(block.getSize())
block.getBytes(addr, text_section)

pattern_list = []
for address in refs:
    pat = generate_signature(address)
    if pat is not None:
        pattern_list.append(pat)

if len(pattern_list) == 0:
    print("=====BIGCHEESE_START=====")
    print(":x: No matches found.")
    print("=====BIGCHEESE_END=====")
else:
    pattern_list.sort(key=lambda x: x.size())

    sig = pattern_list[0]
    sym = getSymbolAt(addr)

    addr_str = addr.toString("")
    sym_str = sym.getName()
    sig_str = str(sig)

    print("=====BIGCHEESE_START=====")
    print("Signature for `" + addr_str + "` (`" + sym_str + "`):")
    print("`" + sig_str + "`")
    print("=====BIGCHEESE_END=====")
