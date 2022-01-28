from typing import List
import sys

SECTION = 40

SYMBOL_TYPES = {
    0: "NOTYPE",
    1: "OBJECT",
    2: "FUNC",
    3: "SECTION",
    4: "FILE",
    5: "COMMON",
    6: "TLS",
    10: "LOOS",
    12: "HIOS",
    13: "LOPROC",
    15: "HIPROC"
}
BIND_TYPES = {
    0: "LOCAL",
    1: "GLOBAL",
    2: "WEAK",
    10: "LOOS",
    12: "HIOS",
    13: "LOPROC",
    15: "HIPROC"
}
SYMBOL_VIS = {
    0: "DEFAULT",
    1: "INTERVAL",
    2: "HIDDEN",
    3: "PROTECTED"
}
SYMBOL_IND = {
    0: "UNDEF",
    0xff00: "LORESERVE",
    0xff1f: "HIPROC",
    0xff20: "LOOS",
    0xff3f: "HIOS",
    0xfff1: "ABS",
    0xfff2: "COMMON",
    0xffff: "XINDEX",
}
ABI_REGS = {
    0: "zero",
    1: "ra",
    2: "sp",
    3: "gp",
    4: "tp",
    5: "t0",
    6: "t1",
    7: "t2",
    8: "s0",
    9: "s1",
    10: "a0",
    11: "a1",
    12: "a2",
    13: "a3",
    14: "a4",
    15: "a5",
    16: "a6",
    17: "a7",
    18: "s2",
    19: "s3",
    20: "s4",
    21: "s5",
    22: "s6",
    23: "s7",
    24: "s8",
    25: "s9",
    26: "s10",
    27: "s11",
    28: "t3",
    29: "t4",
    30: "t5",
    31: "t6",
}
ABI_REGS_COMPRESSED = {
    0: "s0",
    1: "s1",
    2: "a0",
    3: "a1",
    4: "a2",
    5: "a3",
    6: "a4",
    7: "a5"
}
REGS_CSR = {
    0x001: "fflags",
    0x002: "frm",
    0x003: "fcsr",
    0xc00: "cycle",
    0xc01: "time",
    0xc02: "instret",
    0xc80: "cycleh",
    0xc81: "timeh",
    0xc82: "instreth"
}


def get_bytes(start, length, cc=10):
    res = 0
    for i in range(start + length - 1, start - 1, -1):
        res <<= 8
        res += stream[i]
    if cc == 16:
        return hex(res)
    return res


class Header:
    counter = 0

    def __init__(self) -> None:
        self.e_ident = {
            "EI_MAG0": get_bytes(self.counter, 3),
            "EI_CLASS": get_bytes(self.counter + 4, 1),
            "EI_DATA": get_bytes(self.counter + 5, 1),
            "EI_VERSION": get_bytes(self.counter + 6, 1),
            "EI_OSABI": get_bytes(self.counter + 7, 1),
            "EI_ABIVERSION": get_bytes(self.counter + 8, 1),
            "EI_PAD": get_bytes(self.counter + 9, 1)
        }
        self.counter += 28
        self.e_phoff = get_bytes(28, 4)
        self.e_shoff = get_bytes(32, 4)
        self.e_shnum = get_bytes(48, 2)
        self.e_shstrndx = get_bytes(50, 2)


class Section:
    start = 0

    def __init__(self, start) -> None:
        self.sh_name = get_bytes(start, 4)
        self.sh_type = get_bytes(start + 4, 4)
        self.sh_flags = get_bytes(start + 8, 4)
        self.sh_addr = get_bytes(start + 12, 4)
        self.sh_offset = get_bytes(start + 16, 4)
        self.sh_size = get_bytes(start + 20, 4)
        self.sh_link = get_bytes(start + 24, 4)
        self.sh_info = get_bytes(start + 28, 4)
        self.sh_addralign = get_bytes(start + 32, 4)
        self.sh_entsize = get_bytes(start + 36, 4)


class SymbolTable:

    def __init__(self, start) -> None:
        self.st_name = get_bytes(start, 4)
        self.st_value = get_bytes(start + 4, 4)
        self.st_size = get_bytes(start + 8, 4)
        self.st_info = get_bytes(start + 12, 1)
        self.st_other = get_bytes(start + 13, 1)
        self.st_shndx = get_bytes(start + 14, 2)
        self.st_bind = self.st_info >> 4
        self.st_type = self.st_info & 15
        self.st_vis = self.st_other & 3

if len(sys.argv)<3:
    print("Count of args must be 3 or higher")
    exit(403)

try:
    f = open(sys.argv[1], "rb")
    stream = f.read()
    f.close()
except Exception:
    print("Error while working with input file.")
    print("Interrupring")
    exit(404)

try:
    head = Header()
    sections = []
    sym_table_rows = []
    code_arr = []
    labels = {}


    def parse_sections(header: Header, sections: object) -> None:
        for i in range(header.e_shnum):
            sections.append(Section(head.e_shoff + 40 * i))


    def parseSectionName(header: Header, section: Section, sections: object) -> str:
        shstrtab = sections[header.e_shstrndx]
        res = chr(get_bytes(section.sh_name + shstrtab.sh_offset, 1))
        for i in range(1, 400):
            cr = chr(get_bytes(section.sh_name + shstrtab.sh_offset + i, 1))
            if get_bytes(section.sh_name + shstrtab.sh_offset + i, 1) == 0:
                break
            res = res + cr
        return res


    def print_parsed_symbol_table_rows(sym_table: SymbolTable, str_table: Section, deltaOff: int):
        res = ""
        res = "[" + str(deltaOff).rjust(4) + "] " + hex(sym_table.st_value).ljust(17) + " " + str(
            sym_table.st_size).rjust(5) + " " + SYMBOL_TYPES[sym_table.st_type].ljust(8) + " " + BIND_TYPES[
                  sym_table.st_bind].ljust(8) + " " + str(SYMBOL_VIS[sym_table.st_vis]).ljust(8) + " "

        if (sym_table.st_shndx in SYMBOL_IND):
            res += str(SYMBOL_IND[sym_table.st_shndx]).rjust(6)
        else:
            res += str(sym_table.st_shndx).rjust(6)
        res += " "
        res += parse_label_name(sym_table, str_table)
        return res


    def parse_label_name(sym_table_row: SymbolTable, str_row_table: Section) -> str:
        res = ""
        for i in range(100000):
            c = get_bytes(sym_table_row.st_name + str_row_table.sh_offset + i, 1)
            if c == 0:
                break
            res += chr(c)
        return (res)


    def getSectionByName(header: Header, sections: object, name: str) -> Section:
        for el in sections:
            if parseSectionName(header, el, sections) == name:
                return el
        raise ValueError("Section {0} not found".format(name))


    def parse_symbol_table_rows(symtab: Section, sym_table_rows: object) -> None:
        for i in range(symtab.sh_size // 16):
            sym_table_rows.append(SymbolTable(symtab.sh_offset + 16 * i))


    def parse_code_blocks(code: Section, code_arr: object) -> None:
        for i in range(code.sh_size // 4):
            code_arr.append(bin(get_bytes(code.sh_offset + i * 4, 4))[2:].rjust(32, "0"))


    def get_num_from_bin_signed(x: str):
        res = 0
        for i in range(1, len(x)):
            if x[i] == "1":
                res += 1 << (len(x) - 1 - i)
        if x[0] == "1":
            res -= 1 << (len(x) - 1)
        return (res)


    def get_num_from_bin_unsigned(x: str):
        res = 0
        for i in x:
            res = res * 2
            res += int(i)
        return res


    class LabelsFormated:
        def __init__(self, symtab_rows: List[SymbolTable], str_row_table_section: Section) -> None:
            self.labels_human = {}
            self.unnamed_counter = 0
            self.maxLen = 9
            self.parse_labels_symtab(symtab_rows, str_row_table_section)

        def parse_labels_symtab(self, sym_table_rows: List[SymbolTable], str_row_table_section: Section):
            for item in sym_table_rows:
                if (SYMBOL_TYPES[item.st_type] == "FUNC"):
                    name = parse_label_name(item, str_row_table_section)
                    if len(name) > 0 and name != " ":
                        labels[item.st_value] = name
            self.labels_human = labels

        def add_unnamed_label(self, address: int):
            if not address in self.labels_human:
                self.labels_human[address] = "LOC_{0}".format(hex(self.unnamed_counter)[2:].rjust(5, "0"))
                self.unnamed_counter += 1

        def get_label(self, address: int, round: int) -> str:
            for i in range(address, address + round + 1):
                if i in self.labels_human and not "LOC_" in self.labels_human[address]:
                    return self.labels_human[address]
            for i in range(address, address + round + 1):
                if i in self.labels_human:
                    return self.labels_human[address]
            return ""

        def countMaxLen(self):
            for ch in self.labels_human:
                self.maxLen = max(self.maxLen, len(self.labels_human[ch]))

        def print_label(self, out, address: int, offset: int):
            label = self.get_label(address, offset)
            # out.write("{:>{length}}".format(label, length = self.maxLen))
            out.write("{:>{length}}".format(label, length=10))
            if (label and len(label) > 0):
                out.write(": ")
            else:
                out.write("  ")

        def print_empty_label(self, out):
            out.write("{:>{length}}  ".format("", length=10))


    def parseLX(cmd: str):
        func3 = cmd[-15:-12]
        rd_cmd = get_num_from_bin_unsigned(cmd[-12:-7])
        rs_cmd = get_num_from_bin_unsigned(cmd[-12:-7])
        name = ""
        rs1 = ABI_REGS[rs_cmd]
        rd = ABI_REGS[rd_cmd]
        offset = get_num_from_bin_signed(cmd[-32:-20])
        if func3 == "000":
            name = "lb"
        elif func3 == "001":
            name = "lh"
        elif func3 == "010":
            name = "lw"
        elif func3 == "100":
            name = "lbu"
        elif func3 == "101":
            name = "lhu"
        else:
            raise Exception("function not found")
        return "{0}   {1},{2}({3})".format(name, rd, offset, rs1)


    def parseR(cmd: str):
        rd = cmd[20:25]
        funct3 = cmd[17:20]
        rs1 = cmd[12:17]
        rs2 = cmd[7:12]
        funct7 = cmd[0:7]
        operation = ""
        if funct7 == "0000000":
            if funct3 == "000":
                operation = "add"
            elif funct3 == "001":
                operation = "sll"
            elif funct3 == "010":
                operation = "slt"
            elif funct3 == "100":
                operation = "xor"
            elif funct3 == "101":
                operation = "srl"
            elif funct3 == "110":
                operation = "or"
            elif funct3 == "111":
                operation = "and"
            else:
                operation = "unknown_command"
        elif funct7 == "0000001":
            if funct3 == "000":
                operation = "mul"
            elif funct3 == "001":
                operation = "mulh"
            elif funct3 == "011":
                operation = "mulhu"
            elif funct3 == "101":
                operation = "divu"
            elif funct3 == "110":
                operation = "rem"
            elif funct3 == "111":
                operation = "remu"
            else:
                operation = "unknown_command"
        elif funct7 == "0100000":
            if funct3 == "000":
                operation = "sub"
            elif funct3 == "101":
                operation = "sra"
            else:
                operation = "unknown_command"
        else:
            operation = "unknown_command"
        if operation == "unknown_command":
            return operation

        return '{0} {1}, {2}, {3}'.format(operation, ABI_REGS[int(rd, 2)], ABI_REGS[int(rs1, 2)], ABI_REGS[int(rs2, 2)])


    def parseshamt(bin: str) -> str:
        return (int(bin, 2))


    def parseI(cmd: str) -> str:
        rd = cmd[20:25]
        funct3 = cmd[17:20]
        rs1 = cmd[12:17]
        imm = cmd[0:12]

        shamt = cmd[7:12]
        funct7 = cmd[0:7]
        operation = "unknown_command"

        if funct3 == "000":
            operation = "addi"
        elif funct3 == "001":
            if funct7 == "0000000":
                operation = "slli"
                return '{0} {1}, {2}, {3}'.format(operation, ABI_REGS[int(rd, 2)], ABI_REGS[int(rs1, 2)],
                                                  parseshamt(shamt))
            else:
                return "unknown_command"
        elif funct3 == "010":
            operation = "slti"
        elif funct3 == "011":
            operation = "SLTIU"
        elif funct3 == "100":
            operation = "xori"
        elif funct3 == "101":
            if funct7 == "0000000":
                operation = "srli"
            elif funct7 == "0100000":
                operation = "srai"
            else:
                return "unknown_command"
            return '{0} {1}, {2}, {3}'.format(operation, ABI_REGS[int(rd, 2)], ABI_REGS[int(rs1, 2)], parseshamt(shamt))
        elif funct3 == "110":
            operation = "ori"
        elif funct3 == "111":
            operation = "andi"

        return '{0} {1}, {2}, {3}'.format(operation, ABI_REGS[int(rd, 2)], ABI_REGS[int(rs1, 2)],
                                          get_num_from_bin_signed(imm))


    def parseLoadI(cmd: str) -> str:
        rd = cmd[20:25]
        funct3 = cmd[17:20]
        rs1 = cmd[12:17]
        imm = cmd[0:12]
        operation = "unknown_command"

        if funct3 == "000":
            operation = "lb"
        elif funct3 == "001":
            operation = "lh"
        elif funct3 == "010":
            operation = "lw"
        elif funct3 == "100":
            operation = "lbu"
        elif funct3 == "101":
            operation = "lhu"
        if operation != "nvalid":
            return '{0} {1}, {2}({3})'.format(operation, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm),
                                              ABI_REGS[int(rs1, 2)])
        return operation


    def parseB(cmd: str, address: int, labels: LabelsFormated) -> str:
        func3 = cmd[17:20]
        rs1 = cmd[12:17]
        rs2 = cmd[7:12]
        immL = cmd[0:7]
        immR = cmd[20:25]
        operation = "unknown_command"

        imm = immL[0] + immR[-1] + immL[1:] + immR[:-1] + "0"

        if func3 == "000":
            operation = "beq"
        elif func3 == "001":
            operation = "bne"
        elif func3 == "100":
            operation = "blt"
        elif func3 == "101":
            operation = "bqe"
        elif func3 == "110":
            operation = "bltu"
        elif func3 == "111":
            operation = "bgeu"
        else:
            return "unknown_command"

        # Генерируем метку новую, если это конечно имеет смысл
        markInd = address + get_num_from_bin_signed(imm)

        labels.add_unnamed_label(markInd)
        return '{0} {1}, {2}, {4}'.format(operation, ABI_REGS[int(rs1, 2)], ABI_REGS[int(rs2, 2)],
                                          get_num_from_bin_signed(imm), labels.get_label(markInd, 3))


    def parseLui(cmd: str) -> str:
        command = "lui"
        rd = cmd[20:25]
        imm = cmd[0:20]
        return "{0} {1}, {2}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm))


    def parseJal(cmd: str, address: int, labels: LabelsFormated) -> str:
        command = "jal"
        rd = cmd[20:25]
        t = cmd[:19]
        imm = t[0] + t[12:20] + t[11] + t[1:11] + "0"
        markInd = address + get_num_from_bin_signed(imm)

        labels.add_unnamed_label(markInd)
        return "{0} {1}, {3}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm),
                                     labels.get_label(markInd, 3))


    def parseJalR(cmd: str) -> str:
        rs1 = cmd[12:17]
        rd = cmd[20:25]
        imm = cmd[0:12]
        command = "jalr"

        return '{0} {1}, {3}({2})'.format(command, ABI_REGS[int(rd, 2)], ABI_REGS[int(rs1, 2)],
                                          get_num_from_bin_signed(imm))


    def parseAuipc(cmd: str) -> str:
        rd = cmd[20:25]
        imm = cmd[0:20]
        command = "auipc"

        return "{0} {1}, {2}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm))


    def parseS(cmd: str) -> str:
        imm = cmd[0:7] + cmd[20:25]
        funct3 = cmd[17:20]
        rs1 = cmd[12:17]
        rs2 = cmd[7:12]
        operation = "unknown_command"
        if funct3 == "000":
            operation = "sb"
        elif funct3 == "001":
            operation = "sh"
        elif funct3 == "010":
            operation = "sw"
        return "{0} {1}, {3}({2})".format(operation, ABI_REGS[int(rs2, 2)], ABI_REGS[int(rs1, 2)],
                                          get_num_from_bin_signed(imm))


    def parseCSR(cmd: str) -> str:
        imm = cmd[0:12]
        funct3 = cmd[17:20]
        rd = cmd[20:25]
        operation = "unknown_command"

        if cmd[:-7] == "0000000000000000000000000":
            return "ecall"
        elif cmd[:-7] == "0000000000010000000000000":
            return "ebreak"
        else:
            csr = "unknown_command"
            if int(imm, 2) in REGS_CSR:
                csr = REGS_CSR[int(imm, 2)]
            else:
                return csr
            if funct3 == "001":
                operation = "CSRRW"
            elif funct3 == "010":
                operation = "CSRRS"
            elif funct3 == "011":
                operation = "CSRRC"
            elif funct3 == "101":
                operation = "CSRRWI"
            elif funct3 == "110":
                operation = "CSRRSI"
            elif funct3 == "111":
                operation = "CSRRCI"
            else:
                return operation
            if operation[-1] == "I":
                uimm = cmd[12:17]
                return "{0} {1}, {2}, {3}".format(operation, ABI_REGS[int(rd, 2)], csr, int(uimm, 2))
            rs1 = cmd[12:17]
            return "{0} {1}, {2}, {3}".format(operation, rd, csr, ABI_REGS[int(rs1, 2)])
        return "unknown_command"


    def parse4BitCMD(cmd: str, address: int, labels: LabelsFormated):
        opcode = cmd[-7:]
        if opcode == "0110011":
            return parseR(cmd)
        elif opcode == "0010011":
            return parseI(cmd)
        elif opcode == "0000011":
            return parseLoadI(cmd)
        elif opcode == "1100011":
            return parseB(cmd, address, labels)
        elif opcode == "0110111":
            return parseLui(cmd)
        elif opcode == "1101111":
            return parseJal(cmd, address, labels)
        elif opcode == "1100111":
            return parseJalR(cmd)
        elif opcode == "0010111":
            return parseAuipc(cmd)
        elif opcode == "0100011":
            return parseS(cmd)
        elif opcode == "1110011":
            return parseCSR(cmd)
        return "unknown_command"


    def parseAddi4Spn(cmd: str):
        t = cmd[3:-5]
        imm = t[2:6] + t[:2] + t[-1] + t[-2] + 2 * "0"
        rd = cmd[-5:-2]
        command = "c.addi4spn"

        if int(imm, 2) == 0:
            return "unknown_command"
        return "{0} {1}, {2}, {3}".format(command, ABI_REGS_COMPRESSED[int(rd, 2)], "sp", int(imm, 2))


    def parseLW2b(cmd: str) -> str:
        imm = cmd[-6] + cmd[-13:-10] + cmd[-7] + 2 * "0"
        rs = cmd[-10: -7]
        rd = cmd[-5:-2]
        command = "c.lw"
        return "{0} {1}, {2}({3})".format(command, ABI_REGS_COMPRESSED[int(rd, 2)], int(imm, 2),
                                          ABI_REGS_COMPRESSED[int(rs, 2)])


    def parseSW2b(cmd: str) -> str:
        imm = cmd[-6] + cmd[-13:-10] + cmd[-7] + 2 * "0"
        rs = cmd[-10: -7]
        rs2 = cmd[-5:-2]
        command = "c.sw"
        return "{0} {1}, {2}({3})".format(command, ABI_REGS_COMPRESSED[int(rs2, 2)], int(imm, 2),
                                          ABI_REGS_COMPRESSED[int(rs, 2)])


    def parseADDI2(cmd: str) -> str:
        imm = cmd[3] + cmd[-7:-2]
        rd = cmd[-12:-7]
        command = "c.addi"
        if int(rd, 2) == 0:
            return "unknown_command"
        if get_num_from_bin_signed(imm) == 0:
            return "unknown_command"
        return "{0} {1}, {2}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm))


    def parseJAL2(cmd: str, address: int, labels: LabelsFormated):
        t = cmd[-13:-2]
        command = "c.jal"
        imm = t[0] + t[4] + t[2:4] + t[6] + t[5] + t[-1] + t[1] + t[-4:-1] + "0"
        markInd = address + int(imm, 2)
        labels.add_unnamed_label(markInd)

        return "{0} {1}".format(command, labels.get_label(markInd, 3))


    def parseLI2(cmd: str) -> str:
        imm = cmd[3] + cmd[-7:-2]
        command = "c.li"
        rd = cmd[-12:-7]
        if rd == "00000":
            return "unknown_command"
        return "{0} {1}, {2}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm))


    def parseAddi16Sp(cmd: str) -> str:
        imm = cmd[-13] + cmd[-5:-3] + cmd[-6] + cmd[-3] + cmd[-7] + 4 * "0"
        command = "c.addi16sp"
        if get_num_from_bin_signed(imm) == 0:
            return "unknown_command"
        return "{0} sp, {1}".format(command, get_num_from_bin_signed(imm))


    def parseLui2(cmd: str) -> str:
        rd = cmd[-12:-7]
        imm = cmd[-13] + cmd[-7:-2] + 12 * "0"
        command = "c.lui"
        if get_num_from_bin_signed(imm) == 0:
            return "unknown_command"
        return "{0} {1}, {2}".format(command, ABI_REGS[int(rd, 2)], get_num_from_bin_signed(imm))


    def parseAddi16SpAndLui(cmd: str) -> str:
        rd = cmd[-12:-7]
        if int(rd, 2) == 2:
            return parseAddi16Sp(cmd)
        elif int(rd, 2) != 0:
            return parseLui2(cmd)
        return "unknown_command"


    def parseBlock100(cmd: str) -> str:
        imm = cmd[-13] + cmd[-7:-2]
        rd = cmd[-10:-7]
        funct3 = cmd[-12:-10]
        rs2 = cmd[-5:-2]

        operation = "unknown_command"
        if funct3 == "00":
            if int(imm, 2) != 0:
                return "{0} {1}, {2}".format("c.srli", ABI_REGS_COMPRESSED[int(rd, 2)], int(imm, 2))
        elif funct3 == "01":
            if int(imm, 2) != 0:
                return "{0} {1}, {2}".format("c.srai", ABI_REGS_COMPRESSED[int(rd, 2)], int(imm, 2))
        elif funct3 == "10":
            return "{0} {1}, {2}".format("c.andi", ABI_REGS_COMPRESSED[int(rd, 2)], get_num_from_bin_signed(imm))
        else:
            funct4 = cmd[-7:-5]
            t = cmd[-13]
            op = "unknown_command"

            if t == "0":
                if funct4 == "00":
                    op = "c.sub"
                elif funct4 == "01":
                    op = "c.xor"
                elif funct4 == "10":
                    op = "c.or"
                else:
                    op = "c.and"
                return "{0} {1}, {2}".format(op, ABI_REGS_COMPRESSED[int(rd, 2)], ABI_REGS_COMPRESSED[int(rs2, 2)])
        return operation


    def parseJ2(cmd: str, address: int, labels: LabelsFormated):
        t = cmd[-13:-2]
        command = "c.j"
        imm = t[0] + t[4] + t[2:4] + t[6] + t[5] + t[-1] + t[1] + t[-4:-1] + "0"
        markInd = address + get_num_from_bin_signed(imm)
        labels.add_unnamed_label(markInd)
        return "{0} {1}".format(command, labels.get_label(markInd, 1))


    def parseBEQZBNEZ(cmd: str, address: int, labels: LabelsFormated, command: str) -> str:
        rs1 = cmd[-10:-7]
        imm = cmd[-13] + cmd[-7:-5] + cmd[-3] + cmd[-12:-10] + cmd[-5:-3] + "0"
        markInd = address + get_num_from_bin_signed(imm)
        labels.add_unnamed_label(markInd)
        return "{0} {1}, {3}".format(command, ABI_REGS_COMPRESSED[int(rs1, 2)], get_num_from_bin_signed(imm),
                                     labels.get_label(markInd, 1))


    def parseSLLI2(cmd: str) -> str:
        rd = cmd[-12:-7]
        imm = cmd[-13] + cmd[-7:-2]
        if int(imm, 2) == 0 or int(rd, 2) == 0:
            return "unknown_command"
        return "{0} {1}, {2}".format("c.slli", ABI_REGS[int(rd, 2)], int(imm, 2))


    def parseLWSP(cmd: str) -> str:
        rd = cmd[-12:-7]
        imm = cmd[-4:-2] + cmd[-13] + cmd[-7:-4] + 2 * "0"
        if int(rd) == 0:
            return "unknown_command"
        return "{0} {1}, {2}(sp)".format("c.lwsp", ABI_REGS[int(rd, 2)], int(imm, 2))


    def parseSys2(cmd: str, address: int, labels: LabelsFormated) -> str:
        rs1 = cmd[-12:-7]
        rs2 = cmd[-7:-2]
        c = cmd[-13]
        if c == "0":
            if int(rs1, 2) == 0:
                return "unknown_command"
            if int(rs2, 2) == 0:
                return "{0} {1}".format("c.jr", ABI_REGS[int(rs1, 2)])
            else:
                return "{0} {1}, {2}".format("c.mv", ABI_REGS[int(rs1, 2)], ABI_REGS[int(rs2, 2)])
        else:
            if int(rs1, 2) == 0 and int(rs2, 2) == 0:
                return "c.ebreak"
            elif int(rs2, 2) == 0:
                return "{0} {1}".format("c.jalr", ABI_REGS[int(rs1, 2)])
            elif int(rs1, 2) != 0 and int(rs2, 2) != 0:
                return "{0} {1}, {2}".format("c.add", ABI_REGS[int(rs1, 2)], ABI_REGS[int(rs2, 2)])
        return "unknown_command"


    def parseSWDSP2(cmd: str, command: str) -> str:
        rs2 = cmd[-7:-2]
        if command == "c.swsp":
            imm = cmd[-9:-7] + cmd[-13:-9] + 2 * "0"
        else:
            imm = cmd[-10:-7] + cmd[-13:-10] + 2 * "0"
        return "{0} {1}, {2}(sp)".format(command, ABI_REGS[int(rs2, 2)], int(imm, 2))


    def parse2BitCMD(cmd: str, address: int, labels: LabelsFormated):
        funct1 = cmd[-2:]
        funct2 = cmd[:3]

        if funct1 == "00":
            if funct2 == "000":
                return parseAddi4Spn(cmd)
            elif funct2 == "010":
                return parseLW2b(cmd)
            elif funct2 == "110":
                return parseSW2b(cmd)
            else:
                return "unknown_command"
        elif funct1 == "01":
            # NOP (хз)
            if funct2 == "000":
                return parseADDI2(cmd)
            elif funct2 == "001":
                return parseJAL2(cmd, address, labels)
            elif funct2 == "010":
                return parseLI2(cmd)
            elif funct2 == "011":
                return parseAddi16SpAndLui(cmd)
            elif funct2 == "100":
                return parseBlock100(cmd)
            elif funct2 == "101":
                return parseJ2(cmd, address, labels)
            elif funct2 == "110":
                return parseBEQZBNEZ(cmd, address, labels, "c.beqz")
            elif funct2 == "111":
                return parseBEQZBNEZ(cmd, address, labels, "c.bnez")
        elif funct1 == "10":
            if funct2 == "000":
                return parseSLLI2(cmd)
            elif funct2 == "010":
                return parseLWSP(cmd)
            elif funct2 == "100":
                return parseSys2(cmd, address, labels)
            elif funct2 == "110":
                return parseSWDSP2(cmd, "c.swsp")
            elif funct2 == "111":
                return parseSWDSP2(cmd, "c.sdsp")
        return "unknown_command"


    parse_sections(head, sections)
    

    strtab = getSectionByName(head, sections, ".strtab")
    
    symtab = getSectionByName(head, sections, ".symtab")
    
    code = getSectionByName(head, sections, ".text")
    
    
    parse_symbol_table_rows(symtab, sym_table_rows)
    
    labels_formated = LabelsFormated(sym_table_rows, strtab)

    parse_code_blocks(code, code_arr)

    i = code.sh_offset

    try:
        out = open(sys.argv[2], "w")
        out.write(".text\n")
    except Exception:
        print("Error while working with output file.")
        print("Interrupring")
        exit(404)

    while True:
        command = get_bytes(i, 4)
        address = code.sh_addr + i - code.sh_offset
        b4cmd = parse4BitCMD(bin(command)[2:].rjust(32, '0'), address, labels_formated)
        if "unknown_command" in b4cmd:
            command = get_bytes(i, 2)
            b2cmd = parse2BitCMD(bin(command)[2:].rjust(16, '0'), address, labels_formated)
            i += 2
        else:
            i += 4
        if i - code.sh_offset >= code.sh_size:
            break
    labels_formated.countMaxLen()
    i = code.sh_offset
    while True:
        command = get_bytes(i, 4)
        address = code.sh_addr + i - code.sh_offset
        b4cmd = parse4BitCMD(bin(command)[2:].rjust(32, '0'), address, labels_formated)
        if "unknown_command" in b4cmd:
            command = get_bytes(i, 2)
            b2cmd = parse2BitCMD(bin(command)[2:].rjust(16, '0'), address, labels_formated)
            out.write(hex(address)[2:].rjust(8, '0') + " ")
            if (not "unknown_command" in b2cmd):
                labels_formated.print_label(out, address, 0)
                out.write(b2cmd)
            else:
                labels_formated.print_empty_label(out)
                out.write("unknown_command")
            i += 2
        else:
            out.write(hex(address)[2:].rjust(8, '0') + " ")
            labels_formated.print_label(out, address, 0)
            out.write(b4cmd)
            i += 4
        out.write("\n")

        if i - code.sh_offset >= code.sh_size:
            break
    out.write("\n.symtab\n")
    out.write("Symbol Value              Size Type     Bind     Vis       Index Name\n")
    for i in range(len(sym_table_rows)):
        out.write(print_parsed_symbol_table_rows(sym_table_rows[i], strtab, i) + "\n")
except Exception as e:
    print("Error while code working")
    print("Error: {}".format(str(e)))
    exit(403)
