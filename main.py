# made by kay1337

import sys
import pefile
from elftools.elf.elffile import ELFFile
from capstone import *
from keystone import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
from z3 import *
import logging
import argparse
import os
import struct
import binascii
import json

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class Utils:
    @staticmethod
    def hexdump(data, addr=0):
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
            ascii_bytes = ''.join((chr(b) if 32 <= b < 127 else '.') for b in chunk)
            result.append(f"{addr+i:08x}  {hex_bytes:<48}  {ascii_bytes}")
        return '\n'.join(result)

    @staticmethod
    def save_json(data, filename):
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        logging.info(f"Data saved to {filename}")

    @staticmethod
    def load_json(filename):
        with open(filename, 'r') as f:
            data = json.load(f)
        logging.info(f"Data loaded from {filename}")
        return data

    @staticmethod
    def convert_address(addr_str):
        try:
            return int(addr_str, 16)
        except ValueError:
            logging.error(f"Invalid address format: {addr_str}")
            return None

    @staticmethod
    def convert_size(size_str):
        try:
            return int(size_str)
        except ValueError:
            logging.error(f"Invalid size format: {size_str}")
            return None

    @staticmethod
    def read_file_chunk(file_path, size=1024, offset=0):
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                return f.read(size)
        except Exception as e:
            logging.error(f"Error reading file chunk: {e}")
            return None

class FileParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.file_type = self.detect_file_type()

    def detect_file_type(self):
        with open(self.file_path, 'rb') as f:
            magic = f.read(4)
            if magic.startswith(b'MZ'):
                return 'PE'
            elif magic.startswith(b'\x7fELF'):
                return 'ELF'
            else:
                return 'Unknown'

    def parse_pe(self):
        try:
            pe = pefile.PE(self.file_path)
            sections = [{
                'Name': section.Name.decode().strip('\x00'),
                'VirtualAddress': section.VirtualAddress,
                'VirtualSize': section.Misc_VirtualSize,
                'SizeOfRawData': section.SizeOfRawData,
                'PointerToRawData': section.PointerToRawData
            } for section in pe.sections]
            imports = [(entry.dll.decode(), [imp.name.decode() if imp.name else None for imp in entry.imports]) 
                       for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
            exports = [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else []
            logging.info("PE file parsed (Extended).")
            return {
                'sections': sections,
                'imports': imports,
                'exports': exports,
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint
            }
        except Exception as e:
            logging.error(f"PE Parse Error (Extended): {e}")
            return None

    def parse_elf(self):
        try:
            with open(self.file_path, 'rb') as f:
                elffile = ELFFile(f)
                sections = [{
                    'Name': section.name,
                    'Type': section['sh_type'],
                    'Address': section['sh_addr'],
                    'Size': section['sh_size']
                } for section in elffile.iter_sections()]
                imports = [tag.needed for tag in elffile.get_section_by_name('.dynamic').iter_tags() if tag.entry.d_tag == 'DT_NEEDED'] if elffile.get_section_by_name('.dynamic') else []
                symtab = elffile.get_section_by_name('.symtab')
                exports = [symbol.name for symbol in symtab.iter_symbols() if symbol['st_info']['type'] == 'STT_FUNC'] if symtab else []
                logging.info("ELF file parsed (Extended).")
                return {
                    'sections': sections,
                    'imports': imports,
                    'exports': exports,
                    'entry_point': elffile.header['e_entry']
                }
        except Exception as e:
            logging.error(f"ELF Parse Error (Extended): {e}")
            return None

    def parse(self):
        if self.file_type == 'PE':
            return self.parse_pe()
        elif self.file_type == 'ELF':
            return self.parse_elf()
        else:
            logging.error("Unsupported file type.")
            return None

class Disassembler:
    def __init__(self, arch='x86', mode=32):
        if arch == 'x86':
            if mode == 32:
                self.md = Cs(CS_ARCH_X86, CS_MODE_32)
            elif mode == 64:
                self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                raise ValueError("Unsupported mode for x86")
        elif arch == 'arm':
            self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif arch == 'mips':
            self.md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
        else:
            raise ValueError("Unsupported architecture")
        self.md.detail = True

    def disassemble(self, code, addr=0x1000):
        instructions = []
        for instr in self.md.disasm(code, addr):
            instructions.append({
                'address': instr.address,
                'mnemonic': instr.mnemonic,
                'op_str': instr.op_str,
                'regs_read': instr.regs_read,
                'regs_write': instr.regs_write,
                'bytes': instr.bytes.hex()
            })
            logging.debug(f"Disassembled: {instr.address:x}: {instr.mnemonic} {instr.op_str}")
        return instructions

    def get_registers_used(self, code, addr=0x1000):
        regs = set()
        for instr in self.md.disasm(code, addr):
            regs.update(instr.regs_read)
            regs.update(instr.regs_write)
        return regs

    def get_instructions_with_memory_access(self, code, addr=0x1000):
        instructions = []
        for instr in self.md.disasm(code, addr):
            if instr.operands and any(op.type == CS_OP_MEM for op in instr.operands):
                instructions.append(instr)
        return instructions

    def filter_instructions(self, code, addr=0x1000, mnemonic_filter=None):
        instructions = []
        for instr in self.md.disasm(code, addr):
            if mnemonic_filter and instr.mnemonic in mnemonic_filter:
                instructions.append(instr)
        return instructions

    def get_control_flow_instructions(self, code, addr=0x1000):
        control_flow_mnemonics = {'jmp', 'je', 'jne', 'jg', 'jge', 'jl', 'jle', 'call', 'ret'}
        instructions = []
        for instr in self.md.disasm(code, addr):
            if instr.mnemonic in control_flow_mnemonics:
                instructions.append(instr)
        return instructions

class Assembler:
    def __init__(self, arch='x86', mode=32):
        if arch == 'x86':
            if mode == 32:
                self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            elif mode == 64:
                self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            else:
                raise ValueError("Unsupported mode for x86")
        elif arch == 'arm':
            self.ks = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        elif arch == 'mips':
            self.ks = Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + KS_MODE_BIG_ENDIAN)
        else:
            raise ValueError("Unsupported architecture")

    def assemble(self, asm_code):
        try:
            encoding, count = self.ks.asm(asm_code)
            machine_code = bytes(encoding)
            logging.debug(f"Assembly: {asm_code} -> Machine Code: {machine_code.hex()}")
            return machine_code
        except KsError as e:
            logging.error(f"Assembly Error: {e}")
            return None

    def assemble_multiple(self, asm_codes):
        machine_codes = []
        for asm in asm_codes:
            mc = self.assemble(asm)
            if mc:
                machine_codes.append(mc)
        return machine_codes

    def disassemble(self, machine_code, addr=0x1000):
        pass

class IRInstruction:
    def __init__(self, address, mnemonic, operands):
        self.address = address
        self.mnemonic = mnemonic
        self.operands = operands

    def __repr__(self):
        return f"{self.address}: {self.mnemonic} {' '.join(self.operands)}"

class IntermediateRepresentation:
    def __init__(self):
        self.instructions = []

    def add_instruction(self, ir_instr):
        self.instructions.append(ir_instr)

    def __iter__(self):
        return iter(self.instructions)

    def to_json(self):
        return json.dumps([{
            'address': instr.address,
            'mnemonic': instr.mnemonic,
            'operands': instr.operands
        } for instr in self.instructions], indent=4)

class Emulator:
    def __init__(self, arch='x86', mode=32):
        if arch == 'x86':
            if mode == 32:
                self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
                self.reg_eip = UC_X86_REG_EIP
            elif mode == 64:
                self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
                self.reg_eip = UC_X86_REG_RIP
            else:
                raise ValueError("Unsupported mode for x86")
        elif arch == 'arm':
            self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.reg_eip = UC_ARM_REG_PC
        elif arch == 'mips':
            self.uc = Uc(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN)
            self.reg_eip = UC_MIPS_REG_PC
        else:
            raise ValueError("Unsupported architecture")
        self.memory = {}
        self.hooks = []
        self._setup_default_hooks()

    def _setup_default_hooks(self):
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self.hook_mem_write)
        self.uc.hook_add(UC_HOOK_MEM_READ, self.hook_mem_read)
        self.uc.hook_add(UC_HOOK_CODE, self.hook_code)

    def hook_mem_write(self, uc, access, address, size, value, user_data):
        logging.info(f"Memory Write: 0x{address:X} -> {value:#x}")

    def hook_mem_read(self, uc, access, address, size, value, user_data):
        logging.info(f"Memory Read: 0x{address:X} <- {value:#x}")

    def hook_code(self, uc, address, size, user_data):
        logging.info(f"Executing Instruction at 0x{address:X}, Size: {size}")

    def map_memory(self, address, size=2*1024*1024, permissions=UC_PROT_ALL):
        try:
            self.uc.mem_map(address, size, permissions)
            logging.info(f"Memory mapped at 0x{address:X} with size {size} bytes.")
        except UcError as e:
            logging.error(f"Memory mapping error: {e}")

    def write_memory(self, address, data):
        try:
            self.uc.mem_write(address, data)
            logging.info(f"Written {len(data)} bytes to 0x{address:X}.")
        except UcError as e:
            logging.error(f"Memory write error: {e}")

    def set_register(self, reg, value):
        try:
            self.uc.reg_write(reg, value)
            logging.info(f"Register {reg} set to {value:#x}.")
        except UcError as e:
            logging.error(f"Register write error: {e}")

    def get_register(self, reg):
        try:
            value = self.uc.reg_read(reg)
            logging.info(f"Register {reg} read as {value:#x}.")
            return value
        except UcError as e:
            logging.error(f"Register read error: {e}")
            return None

    def emulate(self, start_addr, end_addr):
        try:
            self.uc.emu_start(start_addr, end_addr)
            logging.info("Emulation started.")
        except UcError as e:
            logging.error(f"Emulation error: {e}")

    def add_custom_hook(self, address, callback):
        try:
            self.uc.hook_add(UC_HOOK_CODE, callback, begin=address, end=address + 1)
            logging.info(f"Custom hook added at 0x{address:X}.")
        except UcError as e:
            logging.error(f"Custom hook error: {e}")

    def remove_hook(self, hook_id):
        try:
            self.uc.hook_del(hook_id)
            logging.info(f"Hook {hook_id} removed.")
        except UcError as e:
            logging.error(f"Hook removal error: {e}")

class SymbolicExecutor:
    def __init__(self):
        self.solver = Solver()
        self.symbolic_vars = {}

    def create_symbolic_variable(self, name, size=32):
        var = BitVec(name, size)
        self.symbolic_vars[name] = var
        logging.debug(f"Symbolic variable created: {name} ({size} bits)")
        return var

    def add_constraint(self, expr):
        self.solver.add(expr)
        logging.debug(f"Constraint added: {expr}")

    def is_satisfiable(self):
        result = self.solver.check() == sat
        logging.debug(f"Is satisfiable: {result}")
        return result

    def get_model(self):
        if self.is_satisfiable():
            model = self.solver.model()
            logging.debug(f"Model found: {model}")
            return model
        logging.debug("No model found.")
        return None

    def solve_expression(self, expr):
        self.solver.push()
        self.solver.add(expr)
        if self.solver.check() == sat:
            model = self.solver.model()
            self.solver.pop()
            logging.debug(f"Expression solvable: {model}")
            return model
        else:
            self.solver.pop()
            logging.debug("Expression not solvable.")
            return None

    def add_constraints_from_ir(self, ir_instructions):
        for instr in ir_instructions:
            if instr.mnemonic.lower() == 'xor':
                dest = instr.operands[0]
                src = instr.operands[1]
                if dest in self.symbolic_vars and src in self.symbolic_vars:
                    self.add_constraint(self.symbolic_vars[dest] == self.symbolic_vars[dest] ^ self.symbolic_vars[src])
                    logging.debug(f"Symbolic constraint added for XOR: {dest} = {dest} ^ {src}")

class ReverseEngineeringFramework:
    def __init__(self, file_path, arch='x86', mode=32):
        self.file_parser = FileParser(file_path)
        self.disassembler = Disassembler(arch=arch, mode=mode)
        self.assembler = Assembler(arch=arch, mode=mode)
        self.ir = IntermediateRepresentation()
        self.emulator = Emulator(arch=arch, mode=mode)
        self.symbolic_executor = SymbolicExecutor()
        self.arch = arch
        self.mode = mode

    def analyze_file(self):
        parse_result = self.file_parser.parse()
        if parse_result:
            logging.info(f"File Type: {self.file_parser.file_type}")
            logging.info(f"Sections: {parse_result['sections']}")
            logging.info(f"Imports: {parse_result['imports']}")
            logging.info(f"Exports: {parse_result['exports']}")
            Utils.save_json(parse_result, 'analysis_result.json')
        else:
            logging.error("File analysis failed.")

    def disassemble_code(self, code, addr=0x1000):
        instructions = self.disassembler.disassemble(code, addr)
        for instr in instructions:
            logging.info(f"0x{instr['address']:x}: {instr['mnemonic']} {instr['op_str']}")
            ir_instr = IRInstruction(instr['address'], instr['mnemonic'], instr['op_str'].split(', '))
            self.ir.add_instruction(ir_instr)
        Utils.save_json(instructions, 'disassembly_result.json')
        return instructions

    def assemble_code(self, asm_code):
        machine_code = self.assembler.assemble(asm_code)
        if machine_code:
            logging.info(f"Asm Code: {asm_code} -> Machine Code: {machine_code.hex()}")
            Utils.save_json({'asm_code': asm_code, 'machine_code': machine_code.hex()}, 'assembly_result.json')
        return machine_code

    def emulate_code(self, code, address=0x1000):
        self.emulator.map_memory(0x1000000, 1024*1024)
        self.emulator.write_memory(0x1000000, code)
        self.emulator.set_register(self.emulator.reg_eip, 0x1000000)
        self.emulator.emulate(0x1000000, 0x1000000 + len(code))

    def perform_symbolic_execution(self):
        x = self.symbolic_executor.create_symbolic_variable('x', 32)
        y = self.symbolic_executor.create_symbolic_variable('y', 32)
        self.symbolic_executor.add_constraint(x + y == 10)
        if self.symbolic_executor.is_satisfiable():
            model = self.symbolic_executor.get_model()
            logging.info(f"Symbolic Execution Model: {model}")
            model_dict = {str(d): model[d].as_long() for d in model}
            Utils.save_json(model_dict, 'symbolic_execution_model.json')
        else:
            logging.info("No solution found in symbolic execution.")

    def generate_ir_json(self):
        ir_json = self.ir.to_json()
        Utils.save_json(json.loads(ir_json), 'intermediate_representation.json')

    def display_hexdump(self, data, addr=0x0):
        hexdump = Utils.hexdump(data, addr)
        print(hexdump)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Comprehensive Reverse Engineering Framework')
    parser.add_argument('file', help='Path to the binary file to analyze')
    parser.add_argument('--arch', choices=['x86', 'arm', 'mips'], default='x86', help='CPU architecture')
    parser.add_argument('--mode', choices=['32', '64'], default='32', help='CPU mode (32 or 64)')
    parser.add_argument('--disasm', action='store_true', help='Disassemble code')
    parser.add_argument('--asm', metavar='ASM_CODE', help='Assemble assembly code')
    parser.add_argument('--emulate', action='store_true', help='Emulate code')
    parser.add_argument('--symbolic', action='store_true', help='Perform symbolic execution')
    parser.add_argument('--hexdump', action='store_true', help='Show hexdump')
    return parser.parse_args()

def main():
    args = parse_arguments()

    if not os.path.isfile(args.file):
        logging.error(f"File not found: {args.file}")
        sys.exit(1)

    mode = int(args.mode)
    framework = ReverseEngineeringFramework(args.file, arch=args.arch, mode=mode)

    framework.analyze_file()

    if args.disasm:
        with open(args.file, 'rb') as f:
            sample_code = f.read(100)
        disassembled = framework.disassemble_code(sample_code, addr=0x400000)
        framework.generate_ir_json()

    if args.asm:
        asm_code = args.asm
        machine_code = framework.assemble_code(asm_code)
        if machine_code:
            disassembled = framework.disassemble_code(machine_code, addr=0x500000)

    if args.emulate:
        with open(args.file, 'rb') as f:
            code = f.read(100)
        framework.emulate_code(code, address=0x400000)

    if args.symbolic:
        framework.perform_symbolic_execution()

    if args.hexdump:
        with open(args.file, 'rb') as f:
            data = f.read(256)
        framework.display_hexdump(data, addr=0x0)

if __name__ == "__main__":
    main()