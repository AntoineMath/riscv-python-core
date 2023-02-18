import struct
import glob
from enum import Enum
from elftools.elf.elffile import ELFFile

memory = None
regfile = None

class Regfile:
  def __init__(self):
    self.registers = [0]*33
  def __getitem__(self, key):
    return self.registers[key]
  def __setitem__(self, key, value):
    self.registers[key] = value & 0xFFFFFFFF if key else 0

PC = 32

regs_name = ['0', 'ra', 'sp', 'gp', 'tp', 't0', 't1', 't2', 's0', 's1', 'a0', 'a1',
                  'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 's2', 's3', 's4', 's5', 's6', 's7', 's8',
                   's9', 's10', 's11', 't3', 't4', 't5', 't6']

def reset():
  global regfile, memory
  regfile = Regfile()
  memory = b'\x00'*0x4000

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
  # IM and OP
  ADD = SUB = ADDI = ADDW = ADDIW = SUBW = 0b000
  SLLI = 0b001
  SRLI = SRA = SRAI = 0b101
  SLTI = 0b010
  SLTIU = 0b011
  XORI = 0b100
  ORI = 0b110
  ANDI = 0b011

  # BRANCH
  BEQ = 0b000
  BNE = 0b001
  BLT = 0b100
  BGE = 0b101
  BGEU = 0b111
  BLTU = 0b110

  # SYSTEM
  ECALL = 0b000
  CSRRW = 0b001
  CSRRS = 0b010
  CSRRC = 0b011
  CSRRWI = 0b101
  CSRRSI = 0b110
  CSRRCI = 0b111


class Funct7(Enum):
  ADD = 0b0000000 
  SUB = 0b0100000 


def ws(data, addr):
  global memory
  addr -= 0x80000000
  assert addr >= 0 
  assert addr < len(memory)
  memory = memory[:addr] + data + memory[addr+len(data):]


def r32(addr):
  addr -= 0x80000000
  assert addr >= 0 
  assert addr < len(memory)
  return struct.unpack("<I", memory[addr:addr+4])[0]


def dump():
  pp = []
  for i in range(32):
    if i != 0 and i%8 == 0:
      pp += "\n"
    pp += " %3s: %08x" % (regs_name[i], regfile[i])
  pp += "\nPC: %08x" % regfile[PC]
  print("".join(pp))


def sign_extend(x, l):
  if x >> (l-1) == 1:
    return -((1 << l) - x)
  else:
    return x


def bitwise_ops(funct3, a, b):
  if funct3 == Funct3.ADDI:
    return a + b
  elif funct3 == Funct3.SLLI:
    return a << b
  elif funct3 == Funct3.ORI:
    return a | b 
  elif funct3 == Funct3.XORI:
    return a ^ b
  else: raise Exception("funct3: %r" % (funct3))


def step():
  # Instruction fetch
  instruction = r32(regfile[PC])

  # instruction decode
  def gib(s, e):
    # little endian (so start is at the right of the word)
    return (instruction >> s) & ((1 << e-s+1)-1)

  opcode = Ops(gib(0, 6))
  print("%r  %r" % (hex(regfile[PC]), opcode))

  imm_u = gib(12, 31)
  # Note : we shift gib(21, 30) << 1 and not << 0 because we want to be sure instruction is located at an even address.
  imm_j = sign_extend(gib(31, 32) << 20 | gib(21, 30) << 1 | gib(20, 21) << 11 | gib(12, 19) << 12, 21)
  imm_i = sign_extend(gib(20, 31), 12)

  funct3 = Funct3(gib(12, 14))
  rd = gib(7, 11)
  rs1 = gib(15, 19)
  rs2 = gib(20, 24)

  if opcode == Ops.JAL:
    # J-TYPE
    regfile[rd] = regfile[PC] + 4
    regfile[PC] += imm_j 
    #dump()
    return True

  elif opcode == Ops.JALR:
    # I type
    rs1 = gib(15, 19)
    temp = regfile[PC] + 4
    regfile[PC] = regfile[rs1] + imm_i
    regfile[rd] = temp
    return True

  elif opcode == Ops.IMM:
    # I type
    regfile[rd] = bitwise_ops(funct3, regfile[rs1], imm_i)

  elif opcode == Ops.OP:
    funct7 = Funct7(gib(25, 31))

    if funct3 == Funct3.ADD and funct7 == Funct7.ADD:
      regfile[rd] = regfile[rs1] + regfile[rs2]
    elif funct3 == Funct3.SUB and funct7 == Funct7.SUB:
      regfile[rd] = regfile[rs1] - regfile[rs2]
    else: raise Exception("%r funct3: %r, funct7: %r" % (opcode, funct3, funct7))

  elif opcode == Ops.AUIPC:
    # U Type
    regfile[rd] = regfile[PC] + imm_u

  elif opcode == Ops.LUI:
    # U Type
    regfile[rd] = imm_u << 12
    
  elif opcode == Ops.BRANCH:
    # B TYPE 
    # Note : we shift << 1 and not << 0 because we want to be sure instruction is located at an even address.
    offset = gib(31, 32) << 12 | gib(25, 30) << 5 | gib(8, 11) << 1 | gib(7,8) << 11
    offset = sign_extend(offset, 13)
    condition = False

    if funct3 == Funct3.BEQ:
      condition  = regfile[rs1] == regfile[rs2]
    elif funct3 == Funct3.BNE:
      condition = regfile[rs1] != regfile[rs2]
    elif funct3 == Funct3.BLT:
      condition = sign_extend(regfile[rs1], 32) < sign_extend(regfile[rs2], 32)
    elif funct3 == Funct3.BLTU:
      condition = regfile[rs1] < regfile[rs2]
    elif funct3 == Funct3.BGE:
      condition  = sign_extend(regfile[rs1], 32) >= sign_extend(regfile[rs2], 32)
    elif funct3 == Funct3.BGEU:
      condition  = regfile[rs1] >= regfile[rs2]
    else:
      raise Exception("instruction: %r funct3 %r" % (opcode, funct3))

    if condition:
      regfile[PC] += offset
      #dump()
      return True

  elif opcode == Ops.SYSTEM: 
    if funct3 == Funct3.ECALL: # ecall
      if regfile[3] == 1:
        #print("SUCCESS")
          return False
      elif regfile[3] > 1:
        raise Exception("TEST FAILED")

  elif opcode == Ops.MISC: # sytem call ? 
    pass

  else:
    raise Exception("Opcode %r not known" % (opcode) )

  regfile[PC] += 4
  #dump()
  return True 

if __name__ == "__main__":
  for f in glob.glob("riscv-tests/isa/rv32ui-p-*"):
    if f.endswith(".dump"): continue
    reset()
    with open(f, 'rb') as f:
      e = ELFFile(f)
      for s in e.iter_segments():
        if s.header.p_type == "PT_LOAD": # loadable segment
          ws(s.data(), s.header.p_paddr )
      regfile[PC] = 0x80000000
      counter = 0
      print(f"Test: {f.name}")
      while step():
        counter += 1
      print(f"Test: {f.name} : Executed {counter} instructions")