import struct
import glob
from enum import Enum
from elftools.elf.elffile import ELFFile

# TODO: understand why instruction at 80002a7c is 0b0 for riscv-tests/isa/rv32ui-v-add

# 8192 bytes at 0x80000000
memory = b'\x00'*0x4000

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
  BEQ = 0b000
  BNE = 0b001
  BLT = 0b100
  BGE = 0b101

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
    pp += " x%3s: %08x" % (i, regfile[i])
  pp += "\nPC: %08x" % regfile[PC]
  pp += "\n"
  print("".join(pp))

def sign_extend(x, l):
  if x >> (l-1) == 1:
    return -((1 << l) - x)
  else:
    return x

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
  rd = gib(7, 11)

  if opcode == Ops.JAL:
    # J-TYPE
    rd = gib(7, 11)
    imm20 = gib(31, 32) << 20
    # Note : we shift << 1 and not << 0 because we want to be sure instruction is located at an even address.
    imm1 = gib(21, 30) << 1
    imm11 = gib(20, 21) << 11
    imm12 = gib(12, 19) << 12
    offset = imm20 | imm1 | imm11 | imm12
    regfile[rd] = regfile[PC] + 4
    regfile[PC] += offset
    print("PC at: ", hex(regfile[PC]))
    return True

  elif opcode == Ops.JALR:
    # J type
    rs1 = gib(15, 19)
    imm = gib(20, 31)
    regfile[rd] = regfile[PC] + 4
    regfile[PC] += offset
    return True

  elif opcode == Ops.IMM:
    rs1 = gib(15, 19)
    imm = gib(20, 31)
    funct3 = Funct3(gib(12, 14))

    if funct3 == Funct3.ADDI:
      #print("ADDI")
      regfile[rd] = regfile[rs1] + imm
      #print(f"ADDI {rd}, {hex(regfile[rs1])}, {imm}") #TODO: should be -128, check that it working

    elif funct3 == Funct3.SLLI:
      shamt = gib(20, 24)
      regfile[rd] = regfile[rs1] << shamt & 0xFFFFFFFF
      print(f"SLLI {rd}, {rs1}, {shamt}")
    else: raise Exception("%r funct3: %r" % (opcode, funct3))

  elif opcode == Ops.OP:
    rs1 = gib(15, 19)
    imm = gib(20, 31)
    funct3 = Funct3(gib(12, 14))
    funct7 = Funct7(gib(25, 31))

    if funct7 == Funct7.ADD | funct7 == Funct7.SUB:
      regfile[rd] = regfile[rs1] + regfile[imm] 
    else: raise Exception("%r funct7: %r" % (opcode, funct7))

  elif opcode == Ops.AUIPC:
    # U Type
    regfile[rd] = regfile[PC] + imm_u

  elif opcode == Ops.LUI:
    # U Type
    regfile[rd] = imm_u << 12
    
  

  elif opcode == Ops.BRANCH:
    # B TYPE 
    # Note : we shift << 1 and not << 0 because we want to be sure instruction is located at an even address.
    offset = gib(31, 32) << 12 | gib(25, 30) << 5 | gib(8, 11 << 1) | (gib(7,8)) << 11
    funct3 = Funct3(gib(12, 14))
    rs1 = gib(15, 19)
    rs2 = gib(20, 24)
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
      return True

  elif opcode == Ops.SYSTEM: # TODO: understand that
    # Type I
    pass
  elif opcode == Ops.MISC: # sytem call ? 
    pass

  else:
    raise Exception("Opcode %r not known" % (opcode) )

  regfile[PC] += 4
  #dump()

  return True 

if __name__ == "__main__":
  for f in glob.glob("riscv-tests/isa/rv32ui-p-add*"):
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