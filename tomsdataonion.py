#!/usr/bin/python3


# Tom's Data Onion Solution
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



import http.client
import html.parser
import base64
import re
import ipaddress
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
from cryptography.hazmat.primitives.constant_time import bytes_eq
import tomtelvm


tomsWebSite = 'www.tomdalling.com'
subUrl = '/toms-data-onion/'


class Unsplittable(Exception):
	pass


def splitText(text):
	'''Split text into instructions and encoded part
	'''
	pattern = r'(.*)(<~.+~>).*'
	m = re.search(pattern, text, flags=re.MULTILINE|re.DOTALL)
	if not m:
		raise Unsplittable
	return m.group(1), m.group(2)


def getEncoded(bytes):
	text = bytes.decode()
	try:
		instructions, encoded = splitText(text)
	except Unsplittable:
		instructions = text
		encoded = None
	print("\n\n\n")
	print("********************************************************")
	print("******************** Next Layer ************************")
	print("********************************************************\n")
	print(instructions)
	return encoded


def a85decode(encoded):
	return base64.a85decode(encoded, adobe=True)


class WebSiteParser(html.parser.HTMLParser):
	def handle_data(self, data):
		# Simple hack to select the right text block
		if len(data) < 1000:
			return
		self.data = data.encode()


def getInitialEncoded():
	connection = http.client.HTTPSConnection(tomsWebSite)
	connection.request('GET', subUrl)
	response = connection.getresponse()
	responseBody = response.read()
	connection.close()

	parser = WebSiteParser()
	parser.feed(responseBody.decode())
	return getEncoded(parser.data)


def callPeel(encoded, peelFun):
	decoded = a85decode(encoded)
	bytes = peelFun(decoded)
	return getEncoded(bytes)


def peel0(decoded):
	return decoded


def peel1(decoded):
	bytes = bytearray()
	for b in decoded:
		flipped = (b ^ 0x55)
		lsb = flipped & 0x01
		processedB = (flipped >> 1) | (lsb << 7)
		bytes.append(processedB)
	return bytes


def peel2(decoded):
	bytes = bytearray()
	collectNum = 8
	collect = 0
	for b in decoded:
		valid = True
		b2 = b
		while b2:
			valid = not valid
			b2 = b2 & (b2 - 1)
		if valid:
			collectNum -= 1
			collect += (b >> 1) << (7 * collectNum)
		if 0 == collectNum:
			bytes += collect.to_bytes(7, 'big')
			collectNum = 8
			collect = 0
	return bytes


def peel3(decoded):
	textBegin = b'==[ Layer 4/6: '
	knownLen = len(textBegin)
	textMiddle = b'==[ Payload ]==============================================='
	keyLen = 32
	key = bytearray(keyLen)
	for i in range(knownLen):
		key[i] = decoded[i] ^ textBegin[i]
	for i in range(2 * keyLen, len(decoded), keyLen):
		fraction = bytearray(knownLen)
		for j in range(knownLen):
			fraction[j] = decoded[i+j] ^ key[j]
		foundIdx = textMiddle.find(fraction)
		if foundIdx >= 0:
			for k in range(keyLen - knownLen):
				key[knownLen + k] = decoded[i + knownLen + k] ^ textMiddle[foundIdx + knownLen + k]
			break
	extendedKey = ((len(decoded) // keyLen) + 1) * key
	bytes = bytearray()
	for encryptedByte, keyByte in zip(decoded, extendedKey):
		bytes.append(encryptedByte ^ keyByte)
	return bytes


def peel4(decoded):
	def getWordFromPacket(packet, idx):
		return (packet[idx] << 8) + packet[idx + 1]

	def computeChecksum(packet):
		sumHighBytes = sum(packet[0::2])
		sumLowBytes = sum(packet[1::2])
		totalSum = (sumHighBytes << 8) + sumLowBytes
		while totalSum > 0xffff:
			totalSum = (totalSum & 0xffff) + (totalSum >> 16)
		return totalSum

	expectedFrom = ipaddress.IPv4Address('10.1.1.10')
	expectedTo = ipaddress.IPv4Address('10.1.1.200')
	expectedDestPort = 42069
	packetStart = 0
	bytes = bytearray()
	while packetStart < len(decoded):
		totalLen = getWordFromPacket(decoded, packetStart + 2)
		currPacket = decoded[packetStart : (packetStart + totalLen)]
		packetStart += totalLen

		ihl = currPacket[0] & 0x0f
		ipv4HeaderLen = 4 * ihl

		source = ipaddress.IPv4Address(currPacket[12:16])
		if source != expectedFrom:
			continue
		dest = ipaddress.IPv4Address(currPacket[16:20])
		if dest != expectedTo:
			continue

		ipv4HeaderChecksum = computeChecksum(currPacket[:ipv4HeaderLen])
		if 0xffff != ipv4HeaderChecksum:
			continue

		udpPacket = currPacket[ipv4HeaderLen:]
		destPort = getWordFromPacket(udpPacket, 2)
		if destPort != expectedDestPort:
			continue

		udpIpv4PseudoHeader = bytearray(12)
		udpIpv4PseudoHeader[0:8] = currPacket[12:20]
		udpIpv4PseudoHeader[8] = 0x00
		udpIpv4PseudoHeader[9] = 0x11
		udpIpv4PseudoHeader[10:12] = udpPacket[4:6]
		udpChecksum = computeChecksum(udpIpv4PseudoHeader + udpPacket)
		if 0xffff != udpChecksum:
			continue

		udpData = udpPacket[8:]
		bytes += udpData

	return bytes


# Replacement for original exception in /usr/lib/python3/dist-packages/cryptography/hazmat/primitives/keywrap.py
class InvalidUnwrap(Exception):
	pass

# Modifcation of original /usr/lib/python3/dist-packages/cryptography/hazmat/primitives/keywrap.py
def aes_key_unwrap(wrapping_key, wrapping_iv, wrapped_key, backend):
	if len(wrapped_key) < 24:
		raise ValueError("Must be at least 24 bytes")

	if len(wrapped_key) % 8 != 0:
		raise ValueError("The wrapped key must be a multiple of 8 bytes")

	if len(wrapping_key) not in [16, 24, 32]:
		raise ValueError("The wrapping key must be a valid AES key length")

	# Implement RFC 3394 Key Unwrap - 2.2.2 (index method)
	decryptor = Cipher(algorithms.AES(wrapping_key), modes.ECB(), backend).decryptor()

	## Modification: Use given IV
	#aiv = b"\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"
	aiv = wrapping_iv

	r = [wrapped_key[i:i + 8] for i in range(0, len(wrapped_key), 8)]
	a = r.pop(0)
	n = len(r)
	for j in reversed(range(6)):
		for i in reversed(range(n)):
			# pack/unpack are safe as these are always 64-bit chunks
			atr = struct.pack(
			">Q", struct.unpack(">Q", a)[0] ^ ((n * j) + i + 1)
			) + r[i]
			# every decryption operation is a discrete 16 byte chunk so
			# it is safe to reuse the decryptor for the entire operation
			b = decryptor.update(atr)
			a = b[:8]
			r[i] = b[-8:]

	assert decryptor.finalize() == b""

	if not bytes_eq(a, aiv):
		raise InvalidUnwrap()

	return b"".join(r)


def peel5(decoded):
	kek = decoded[0:32]
	kekIv = decoded[32:40]
	encryptedKey =  decoded[40:80]
	payloadIv = decoded[80:96]
	payloadEnc = decoded[96:]

	backend = default_backend()
	decryptedKey = aes_key_unwrap(wrapping_key=kek, wrapping_iv=kekIv, wrapped_key=encryptedKey, backend=backend)
	cipher = Cipher(algorithms.AES(decryptedKey), modes.CTR(payloadIv), backend=backend)

	return cipher.decryptor().update(payloadEnc)


def peel6(decoded):
	vm = tomtelvm.TomtelVm(decoded)
	result = vm.run()
	return result


if __name__ == '__main__':
	encoded0 = getInitialEncoded()
	encoded1 = callPeel(encoded0, peel0)
	encoded2 = callPeel(encoded1, peel1)
	encoded3 = callPeel(encoded2, peel2)
	encoded4 = callPeel(encoded3, peel3)
	encoded5 = callPeel(encoded4, peel4)
	encoded6 = callPeel(encoded5, peel5)
	callPeel(encoded6, peel6)

