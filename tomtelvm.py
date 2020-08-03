#!/usr/bin/python3


# This file is part of Tom's Data Onion Solution
# Copyright (C) 2020  Björn Hendriks
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.



import re


class Register:
	'''For the MV commands we need refs to registers so we create a class for them
	'''

	def __init__(self, bitness):
		self.bitness = bitness
		self.value = 0


class Registers:
	class MemoryCursor:
		def __init__(self, memory, ptr, c):
			self._memory = memory
			self._ptr = ptr
			self._c = c

		def __getattr__(self, name):
			if 'value' != name:
				raise AttributeError()
			return self._memory[self._ptr.value + self._c.value]

		def __setattr__(self, name, value):
			if 'value' == name:
				self._memory[self._ptr.value + self._c.value] = value
			object.__setattr__(self, name, value)

	def __init__(self, memory):
		self.a = Register(8)
		self.b = Register(8)
		self.c = Register(8)
		self.d = Register(8)
		self.e = Register(8)
		self.f = Register(8)
		self.la = Register(32)
		self.lb = Register(32)
		self.lc = Register(32)
		self.ld = Register(32)
		self.ptr = Register(32)
		self.pc = Register(32)

		self.shortRegisters = {
			1: self.a,
			2: self.b,
			3: self.c,
			4: self.d,
			5: self.e,
			6: self.f,
			7: self.MemoryCursor(memory, self.ptr, self.c)
		}

		self.longRegisters = {
			1: self.la,
			2: self.lb,
			3: self.lc,
			4: self.ld,
			5: self.ptr,
			6: self.pc,
		}

	def getShortRegister(self, number):
		return self.shortRegisters[number]

	def getLongRegister(self, number):
		return self.longRegisters[number]


def _getMvSubcode(opcode):
	dest = (opcode & 0x38) >> 3
	src = opcode & 0x07
	return dest, src


class TomtelVm:
	def __init__(self, bytecode):
		self.memory = bytearray(bytecode)
		self.registers = Registers(self.memory)
		self.output = bytearray()

		self.fixedOpcodes = {
			0xC2: self._add,
			0xE1: self._aptr,
			0xC1: self._cmp,
			0x01: self._halt,
			0x21: self._jez,
			0x22: self._jnz,
			0x02: self._out,
			0xC3: self._sub,
			0xC4: self._xor,
		}

	class Halt(Exception):
		'''Raised by HLT instruction'''
		pass

	def run(self):
		instrCount = 0
		try:
			while self.registers.pc.value < len(self.memory):
				currentInstruction = self.memory[self.registers.pc.value : ]
				self._dispatchInstruction(currentInstruction)
				instrCount += 1
			raise RuntimeError("Ran out of the program without encountering HALT instruction")
		except self.Halt:
			return self.output

	def _dispatchInstruction(self, currentInstruction):
		self.registers.pc.value += 1
		opcode = currentInstruction[0]
		mvOpcode = opcode & 0xC0
		args = currentInstruction[1:]
		if 0x40 == mvOpcode:
			self._mv8(opcode, args)
		elif 0x80 == mvOpcode:
			self._mv32(opcode, args)
		else:
			self.fixedOpcodes[opcode](args)

	def _get32BitValue(self, args):
		result = 0
		for i in range(4):
			result += (args[i] << (8 * i))
		self.registers.pc.value += 4
		return result

	def _get8BitValue(self, args):
		self.registers.pc.value += 1
		return args[0]

	def _mv8(self, opcode, args):
		dest, src = _getMvSubcode(opcode)
		if 0 == src:
			srcVal = self._get8BitValue(args)
		else:
			srcVal = self.registers.getShortRegister(src).value
		self.registers.getShortRegister(dest).value = srcVal

	def _mv32(self, opcode, args):
		dest, src = _getMvSubcode(opcode)
		if 0 == src:
			srcVal = self._get32BitValue(args)
		else:
			srcVal = self.registers.getLongRegister(src).value
		self.registers.getLongRegister(dest).value = srcVal

	def _add(self, args):
		self.registers.a.value = (self.registers.a.value + self.registers.b.value) % 256

	def _aptr(self, args):
		self.registers.ptr.value += self._get8BitValue(args)

	def _cmp(self, args):
		if self.registers.a.value == self.registers.b.value:
			self.registers.f.value = 0x00
		else:
			self.registers.f.value = 0x01

	def _halt(self, args):
		raise self.Halt()

	def _jez(self, args):
		newPc = self._get32BitValue(args)
		if 0 == self.registers.f.value:
			self.registers.pc.value = newPc

	def _jnz(self, args):
		newPc = self._get32BitValue(args)
		if 0 != self.registers.f.value:
			self.registers.pc.value = newPc

	def _out(self, args):
		self.output.append(self.registers.a.value)

	def _sub(self, args):
		diff = self.registers.a.value - self.registers.b.value
		if diff < 0:
			diff += 255
		self.registers.a.value = diff

	def _xor(self, args):
		self.registers.a.value = (self.registers.a.value ^ self.registers.b.value)


class Disassembler:
	def __init__(self, bytecode):
		self.memory = bytes(bytecode)

		self.fixedOpcodeInstructions = {
			0x01: 'HALT ',
			0x02: 'OUT   a',
			0x21: 'JEZ  ',
			0x22: 'JNZ  ',
			0xC1: 'CMP  ',
			0xC2: 'ADD   a <- b',
			0xC3: 'SUB   a <- b',
			0xC4: 'XOR   a <- b',
			0xE1: 'APTR ',
		}
		self.shortRegisters = {
			1: 'a',
			2: 'b',
			3: 'c',
			4: 'd',
			5: 'e',
			6: 'f',
			7: '(ptr+c)'
		}
		self.longRegisters = {
			1: 'la',
			2: 'lb',
			3: 'lc',
			4: 'ld',
			5: 'ptr',
			6: 'pc',
		}
		self.imm8Instr = (0xE1, )
		self.imm32Instr = (0x21, 0x22)

	def disassemble(self):
		self._currIdx = 0
		self._text = ""
		try:
			while self._currIdx < len(self.memory):
				currentInstruction = self.memory[self._currIdx : ]
				self._disassembleInstruction(currentInstruction)
			self._text += "\n"
		except KeyError:
			print("Disassembled only", self._currIdx, "of", len(self.memory), "bytes\n")
		return self._text

	def _disassembleInstruction(self, currentInstruction):
		self._text += hex(self._currIdx) + ": "
		self._currIdx += 1
		opcode = currentInstruction[0]
		mvOpcode = opcode & 0xC0
		args = currentInstruction[1:]
		if 0x40 == mvOpcode:
			self._disAssMv8(opcode, args)
		elif 0x80 == mvOpcode:
			self._disAssMv32(opcode, args)
		elif opcode in self.fixedOpcodeInstructions:
			self._text += self.fixedOpcodeInstructions[opcode] + " "
			if opcode in self.imm8Instr:
				self._append8BitNumber(args)
			elif opcode in self.imm32Instr:
				self._append32BitNumber(args)
		else:
			self._append8BitNumber(currentInstruction)
			self._currIdx -= 1
			self._text += " # no instruction"
		self._text += "\n"

	def _append32BitNumber(self, args):
		self._text += "0x"
		for i in reversed(range(4)):
			self._text += hex(args[i])[2:4]
		self._currIdx += 4

	def _append8BitNumber(self, args):
		self._text += str(args[0])
		self._currIdx += 1

	def _disAssMv8(self, opcode, args):
		dest, src = _getMvSubcode(opcode)
		if 0 == src:
			self._text += "MVI   " + self.shortRegisters[dest] + " <- "
			self._append8BitNumber(args)
		else:
			self._text += "MV    " + self.shortRegisters[dest] + " <- " + self.shortRegisters[src]

	def _disAssMv32(self, opcode, args):
		dest, src = _getMvSubcode(opcode)
		if 0 == src:
			self._text += "MVI32 " + self.longRegisters[dest] + " <- "
			self._append32BitNumber(args)
		else:
			self._text += "MV32  " + self.longRegisters[dest] + " <- " + self.longRegisters[src]


def test():
	testProgram = """
		50 48  # MVI b <- 72
		C2     # ADD a <- b
		02     # OUT a
		A8 4D 00 00 00  # MVI32 ptr <- 0x0000004d
		4F     # MV a <- (ptr+c)
		02     # OUT a
		50 09  # MVI b <- 9
		C4     # XOR a <- b
		02     # OUT a
		02     # OUT a
		E1 01  # APTR 0x00000001
		4F     # MV a <- (ptr+c)
		02     # OUT a
		C1     # CMP
		22 1D 00 00 00  # JNZ 0x0000001d
		48 30  # MVI a <- 48
		02     # OUT a
		58 03  # MVI c <- 3
		4F     # MV a <- (ptr+c)
		02     # OUT a
		B0 29 00 00 00  # MVI32 pc <- 0x00000029
		48 31  # MVI a <- 49
		02     # OUT a
		50 0C  # MVI b <- 12
		C3     # SUB a <- b
		02     # OUT a
		AA     # MV32 ptr <- lb
		57     # MV b <- (ptr+c)
		48 02  # MVI a <- 2
		C1     # CMP
		21 3A 00 00 00  # JEZ 0x0000003a
		48 32  # MVI a <- 50
		02     # OUT a
		48 77  # MVI a <- 119
		02     # OUT a
		48 6F  # MVI a <- 111
		02     # OUT a
		48 72  # MVI a <- 114
		02     # OUT a
		48 6C  # MVI a <- 108
		02     # OUT a
		48 64  # MVI a <- 100
		02     # OUT a
		48 21  # MVI a <- 33
		02     # OUT a
		01     # HALT
		65 6F 33 34 2C  # non-instruction data
	"""

	testCode = bytes()
	for programLine in re.finditer(r'^\s*(.*)\s*#.*$', testProgram, flags=re.MULTILINE):
		testCode += bytes.fromhex(programLine.group(1))

	dis = Disassembler(testCode)
	print(dis.disassemble())

	vm = TomtelVm(testCode)
	result = vm.run()
	print(result)

if __name__ == "__main__":
	test()

