import argparse
import json
import prefs
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

class TraceData:
    """TraceData class.
    Class for storing execution trace and bookmarks.
    Attributes:
        filename (str): A trace file name.
        arch (str): CPU architecture.
        ip_reg (str): Name of instruction pointer register
        pointer_size (int): Pointer size (4 in x86, 8 in x64)
        regs (dict): Register names and indexes
        trace (list): A list of traced instructions, registers and memory accesses.
        bookmarks (list): A list of bookmarks.
    """

    def __init__(self):
        """Inits TraceData."""
        self.filename = ""
        self.arch = ""
        self.ip_reg = ""
        self.pointer_size = 0
        self.regs = {}
        self.trace = []
        self.bookmarks = []

    def clear(self):
        """Clears trace and all data"""
        self.trace = []
        self.bookmarks = []

    def get_trace(self):
        """Returns a full trace
        Returns:
            list: Trace
        """
        return self.trace

    def get_regs(self):
        """Returns dict of registers and their indexes
        Returns:
            dict: Regs
        """
        return self.regs

    def get_regs_and_values(self, row):
        """Returns dict of registers and their values
        Returns:
            dict: Register names and values
        """
        registers = {}
        try:
            reg_values = self.trace[row]["regs"]
            for reg_name, reg_index in self.regs.items():
                reg_value = reg_values[reg_index]
                registers[reg_name] = reg_value
        except IndexError:
            print(f"Error. Could not get regs from row {row}.")
            return {}
        return registers

    def get_reg_index(self, reg_name):
        """Returns a register index
        Args:
            reg_name (str): Register name
        Returns:
            int: Register index
        """
        try:
            index = self.regs[reg_name]
        except KeyError:
            print("Unknown register")
        return index

    def get_modified_regs(self, row):
        """Returns modfied regs
        Args:
            row (int): Trace row index
        Returns:
            list: List of register names
        """
        modified_regs = []
        reg_values = self.trace[row]["regs"]
        next_row = row + 1
        if next_row < len(self.trace):
            next_row_data = self.trace[next_row]
            for reg_name, reg_index in self.regs.items():
                reg_value = reg_values[reg_index]
                next_reg_value = next_row_data["regs"][reg_index]
                if next_reg_value != reg_value:
                    modified_regs.append(reg_name)
        return modified_regs

    def get_trace_rows(self, rows):
        """Returns a trace of given rows
        Args:
            rows (list): List of trace indexes
        Returns:
            list: Trace
        """
        trace = []
        try:
            trace = [self.trace[int(i)] for i in rows]
        except IndexError:
            print("Error. Could not get trace rows.")
        return trace

    def get_instruction_pointer_name(self):
        """Returns an instruction pointer name
        Returns:
            str: Instruction pointer name
        """
        if self.ip_reg:
            return self.ip_reg
        elif "eip" in self.regs:
            return "eip"
        elif "rip" in self.regs:
            return "rip"
        elif "ip" in self.regs:
            return "ip"
        elif "pc" in self.regs:
            return "pc"
        return ""

    def get_instruction_pointer(self, row):
        """Returns a value of instruction pointer of given row
        Args:
            row: A row index in trace
        Returns:
            int: Address of instruction
        """
        ip = 0
        ip_reg = self.get_instruction_pointer_name()
        try:
            reg_index = self.regs[ip_reg]
            ip = self.trace[row]["regs"][reg_index]
        except IndexError:
            print(f"Error. Could not get IP from row {row}")
        return ip


def open_x64dbg_trace(filename):
    """Opens x64dbg trace file
    Args:
        filename: name of trace file
    Returns:
        TraceData object
    """
    with open(filename, "rb") as f:
        trace_data = TraceData()
        trace_data.filename = filename

        # check first 4 bytes
        magic = f.read(4)
        if magic != b"TRAC":
            raise ValueError("Error, wrong file format.")

        json_length_bytes = f.read(4)
        json_length = int.from_bytes(json_length_bytes, "little")

        # read JSON blob
        json_blob = f.read(json_length)
        json_str = str(json_blob, "utf-8")
        arch = json.loads(json_str)["arch"]

        reg_indexes = {}
        if arch == "x64":
            regs = prefs.X64_REGS
            ip_reg = "rip"
            capstone_mode = CS_MODE_64
            pointer_size = 8  # qword
        else:
            regs = prefs.X32_REGS
            ip_reg = "eip"
            capstone_mode = CS_MODE_32
            pointer_size = 4  # dword

        for i, reg in enumerate(regs):
            reg_indexes[reg] = i

        trace_data.arch = arch
        trace_data.ip_reg = ip_reg
        trace_data.regs = reg_indexes
        trace_data.pointer_size = pointer_size

        md = Cs(CS_ARCH_X86, capstone_mode)
        reg_values = [None] * len(reg_indexes)
        trace = []
        row_id = 0
        while f.read(1) == b"\x00":
            register_changes = int.from_bytes(f.read(1), "little")
            memory_accesses = int.from_bytes(f.read(1), "little")
            flags_and_opcode_size = int.from_bytes(f.read(1), "little")  # Bitfield
            thread_id_bit = (flags_and_opcode_size >> 7) & 1  # msb
            opcode_size = flags_and_opcode_size & 15  # 4 lsbs

            if thread_id_bit > 0:
                thread_id = int.from_bytes(f.read(4), "little")

            opcodes = f.read(opcode_size)

            register_change_position = []
            for _ in range(register_changes):
                register_change_position.append(int.from_bytes(f.read(1), "little"))

            register_change_new_data = []
            for _ in range(register_changes):
                register_change_new_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_flags = []
            for _ in range(memory_accesses):
                memory_access_flags.append(int.from_bytes(f.read(1), "little"))

            memory_access_addresses = []
            for _ in range(memory_accesses):
                memory_access_addresses.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_old_data = []
            for _ in range(memory_accesses):
                memory_access_old_data.append(
                    int.from_bytes(f.read(pointer_size), "little")
                )

            memory_access_new_data = []
            for i in range(memory_accesses):
                if memory_access_flags[i] & 1 == 0:
                    memory_access_new_data.append(
                        int.from_bytes(f.read(pointer_size), "little")
                    )

            reg_id = 0
            for i, change in enumerate(register_change_position):
                reg_id += change
                if reg_id + i < len(reg_indexes):
                    reg_values[reg_id + i] = register_change_new_data[i]

            # disassemble
            ip_value = reg_values[reg_indexes[ip_reg]]
            for (_address, _size, mnemonic, op_str) in md.disasm_lite(
                    opcodes, ip_value
            ):
                disasm = mnemonic
                if op_str:
                    disasm += " " + op_str

            mems = []
            mem = {}
            new_data_counter = 0
            for i in range(memory_accesses):
                flag = memory_access_flags[i]
                value = memory_access_old_data[i]
                mem["access"] = "READ"
                if flag & 1 == 0:
                    value = memory_access_new_data[new_data_counter]
                    mem["access"] = "WRITE"
                    new_data_counter += 1
                else:
                    pass
                    # memory value didn't change
                    # (it is read or overwritten with identical value)
                    # this has to be fixed somehow in x64dbg

                mem["addr"] = memory_access_addresses[i]

                # fix value (x64dbg saves all values as qwords)
                if "qword" in disasm:
                    pass
                elif "dword" in disasm:
                    value &= 0xFFFFFFFF
                elif "word" in disasm:
                    value &= 0xFFFF
                elif "byte" in disasm:
                    value &= 0xFF
                mem["value"] = value
                mems.append(mem.copy())

            trace_row = {}
            trace_row["id"] = row_id
            trace_row["ip"] = ip_value
            trace_row["disasm"] = disasm
            trace_row["regs"] = reg_values.copy()
            trace_row["opcodes"] = opcodes
            trace_row["mem"] = mems.copy()
            trace_row["comment"] = ""
            trace.append(trace_row)
            row_id += 1

        trace_data.trace = trace
        return trace_data


