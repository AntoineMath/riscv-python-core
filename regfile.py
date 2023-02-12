import struct
import glob
from enum import Enum
from elftools.elf.elffile import ELFFile

regfile = [0]*33
PC = 32
class Ops(Enum):
  LUI = 0b0110111    # load upper immediate
  LOAD = 0b0000011
  STORE = 0b0100011

  AUIPC = 0b0010111  # add upper immediate to pc
  BRANCH = 0b1100011
  JAL = 0b1101111 # 111
  JALR = 0b1100111 # 55

  IMM = 0b0010011
  OP = 0b0110011

  MISC = 0b0001111
  SYSTEM = 0b1110011 # CSR instruction

class Funct3(Enum):
  ADD = SUB = ADDI = 0b000
  SLLI = 0b001
  SRLI = SRA = SRAI = 0b101
  SLTI = 0b010
  SLTIU = 0b011
  XORI = 0b100
  ORI = 0b110
  ANDI = 0b011

class Funct7(Enum):
  ADD = 0b0000000 
  SUB = 0b0100000 

# 4k at 0x80000000
memory = b'\x00'*0x10000

def ws(data, addr):
  global memory
  addr -= 0x80000000 # TODO: understand that
  assert addr >= 0 
  assert addr < len(memory)
  
  memory = memory[:addr] + data + memory[addr+len(data):]

def r32(addr):
  addr -= 0x80000000 # TODO: understand that
  assert addr >= 0 
  assert addr < len(memory)
  return struct.unpack("<I", memory[addr:addr+4])[0]

def dump():
  pp = []
  for i in range(32):
    if i != 0 and i%8 == 0:
      pp += "\n"
    pp += " x%3s: %08x" % (i, regfile[i])
  pp += "\nPC: %08x" % regfile[PC]
  pp += "\n"
  print("".join(pp))


def step():
  # Instruction fetch
  instruction = r32(regfile[PC])

  # instruction decode
  def gib(s, e):
    # little endian (so start is at the right of the word)
    return (instruction >> s) & ((1 << e-s+1)-1)

  print(bin(gib(0,6)))
  opcode = Ops(gib(0, 6))

  if opcode == Ops.JAL:
    print("JAL")
    imm20 = gib(30, 31) << 20
    imm1 = gib(21, 30) << 1
    imm11 = gib(20, 21) << 11
    imm12 = gib(12, 19) << 12
    offset = imm20 | imm1 | imm11 | imm12
    regfile[PC] += offset

  elif opcode == Ops.IMM:
    rd = gib(7, 11) # used for pseudo MV instuction
    rs1 = gib(15, 19)
    imm = gib(20, 31)
    funct3 = Funct3(gib(12, 14))

    if funct3 == Funct3.ADDI:
      regfile[rd] = regfile[rs1] + imm
      print(f"ADDI {hex(rd)}, zero, {rs1}") #TODO: should be -128, check that it working

    elif funct3 == Funct3.SLLI:
      shamt = gib(20, 24)
      regfile[rd] = regfile[rs1] << shamt & 0xFFFFFFFF
      print(f"SLLI {rd}, {rs1}, {shamt}")

    regfile[PC] += 4

  elif opcode == Ops.OP:
    rd = gib(7, 11) # used for pseudo MV instuction
    rs1 = gib(15, 19)
    imm = gib(20, 31)
    funct3 = Funct3(gib(12, 14))
    funct7 = Funct7(gib(25, 31))

    if funct7 == Funct7.ADD:
      print(f"ADD {hex(rd)}, {hex(imm)}, {hex(rs1)}") #TODO: should be -128, check that it working
    if funct7 == Funct7.SUB:
      print(f"SUB {hex(rd)}, hex{imm}, {rs1}") #TODO: should be -128, check that it working
    regfile[rd] = regfile[rs1] + regfile[imm] 

    regfile[PC] += 4

  elif opcode == Ops.AUIPC:
    ins = Uinstruction(instruction)
    offset = ins.imm << 12 
    regfile[ins.rd] = regfile[PC] + offset
    regfile[PC] += 4
  
  elif opcode == Ops.SYSTEM: # TODO: understand that
    print("SYSTEM (don't know what it is)")
    regfile[PC] += 4

  else:
    print(hex(instruction), bin(instruction))
    dump()
    return False

  dump()

  return True 
class Instruction:
  def gib(self, s, e):
    # little endian (so start is at the right of the word)
    return (self.ins>> s) & ((1 << e-s+1)-1)

class Uinstruction(Instruction):
    # 31_______________12_11___7_6_________0
    # |    imm[31:12]    |  rd  |  opcode  |
    # |__________________|______|__________|
  def __init__(self, ins):
    self.type = "U" 
    self.ins = ins
    self.rd = self.gib(7, 11)
    self.imm = self.gib(12, 31)


if __name__ == "__main__":
  counter = 0
  c = 0
  for f in glob.glob("riscv-tests/isa/rv32ui-v*"):
    if f.endswith(".dump"): continue
    with open(f, 'rb') as f:
      print("test", f.name)
      e = ELFFile(f)
      for s in e.iter_segments():
        print(s.header.p_type)
        if (s.header.p_type == "PT_LOAD"):
          ws(s.data(), s.header.p_paddr )
          regfile[PC] = 0x80000000
          while step():
            pass
    break





