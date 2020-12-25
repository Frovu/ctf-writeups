# investigation_encoded_1
Forensics, 450 points

## Disclaimer:
This is not optimal solution, its more like to demonstrate my own learning experience.

## Description:
> We have recovered a binary and 1 file: image01. See what you can make of it.
> NOTE: The flag is not in the normal picoCTF{XXX} format.

I would not call this challenge forensics its more of revers + some crypto imo.

## Solution:
### Analysis
We are given a 20 bytes `output` file and an `ELF 64-bit` binary that produced it.

By decompiling binary with Ghidra we can see that `main()` reads `flag.txt`,
prepares some values and calls `encode()`.

Lets take a closer look at this function decompiled, it looks something like this:
```c
void encode(void)
{
  int is_valid;
  uint tmp;
  int matrix_field;
  char chr;
  char flag_chr;

  while( true ) {
    if (flag_size <= *flag_index) {
      while (remain != 7) {
        save(0);
      }
      return;
    }
    flag_chr = flag[*flag_index];
    is_valid = isValid(flag_chr);
    if ((char)is_valid != '\x01') break;
    tmp = lower(flag_chr);
    chr = (char)tmp;
    if (chr == ' ') {
      chr = '{';
    }
    matrix_field = *(int *)(matrix[chr + -0x61] + 4);
    is_valid = matrix_field + *(int *)matrix[chr + -0x61];
    while (matrix_field < is_valid) {
      tmp = getValue(matrix_field);
      save((byte)tmp);
      matrix_field = matrix_field + 1;
    }
    *flag_index = *flag_index + 1;
  }
  fwrite("Error, I don\'t know why I crashed\n",1,0x22,stderr);
  exit(1);
}
```

We see that 4 other functions are called from here: `isValid()`, `lower()`, `getValue()` and `save()`

The first two are doing exactly what they are named, checking that char is alphabetical symbol and transforming it to lower case.

After these two calls it replaces `' '`  with `'{'` and then gets two values from some `matrix` array in memory, after that it does `save(getValue())` several times.

Lets now look at `getValue()` and `save()` functions:

```c
uint getValue(int param)
{
  byte bVar1;
  int iVar2;

  iVar2 = param;
  if (param < 0) {
    iVar2 = param + 7;
  }
  bVar1 = (byte)(param >> 0x37);
  return (int)(uint)secret[iVar2 >> 3] >>
         (7 - (((char)param + (bVar1 >> 5) & 7) - (bVar1 >> 5)) & 0x1f) & 1;
}

void save(byte param_1)
{
  buffChar = buffChar | param_1;
  if (remain == 0) {
    remain = 7;
    fputc((int)(char)buffChar,output);
    buffChar = '\0';
  }
  else {
    buffChar = buffChar * '\x02';
    remain = remain + -1;
  }
  return;
}
```

Somewhere at this point I got confused by all the bit shifts and thought the decompilation tries to fool me, so I decided to open it with `radare2 (Cutter)` and reimplement functions in python from assembly, to fully understand what they do. Yes its really slow but I was solving this for fun much time after ctf ended.

I got the `secret` and `matrix` globals values from memory dump, but before writing this checked the other writeup of this challenge and learned very cool method of dumping c arrays from memory with `radare2`:

```perl
[0x000007c0]> bf obj.secret
[0x000007c0]> pc @ obj.secret
#define _BUFFER_SIZE 37
const uint8_t buffer[_BUFFER_SIZE] = {
  0xb8, 0xea, 0x8e, 0xba, 0x3a, 0x88, 0xae, 0x8e, 0xe8, 0xaa,
  0x28, 0xbb, 0xb8, 0xeb, 0x8b, 0xa8, 0xee, 0x3a, 0x3b, 0xb8,
  0xbb, 0xa3, 0xba, 0xe2, 0xe8, 0xa8, 0xe2, 0xb8, 0xab, 0x8b,
  0xb8, 0xea, 0xe3, 0xae, 0xe3, 0xba, 0x80
};

```

While rewriting program in python I understood that what its doing essentially is encoding each character to one fixed bit sequence of different length and then writes all this bits into output (with 0 padding to last byte).

### Solution plan

Knowing that each char always produces the same bit sequence I decided to create a map of characters (with reimplemented program logic) and then parse the flag output sequence according to this map.

I thought that sequence parsing may be ambiguous so I decided to write a recursive function that checks for prefix and produces recursive tree with flag at the end.

The recursion exit condition is obviously that there are no '1' bits left in remainder sequence.

### Final solution script

```py
matrix = [
	0x00000008, 0x00000000, 0x0000000c, 0x00000008, 0x0000000e,
	0x00000014, 0x0000000a, 0x00000022, 0x00000004, 0x0000002c,
	0x0000000c, 0x00000030, 0x0000000c, 0x0000003c, 0x0000000a,
	0x00000048, 0x00000006, 0x00000052, 0x00000010, 0x00000058,
	0x0000000c, 0x00000068, 0x0000000c, 0x00000074, 0x0000000a,
	0x00000080, 0x00000008, 0x0000008a, 0x0000000e, 0x00000092,
	0x0000000e, 0x000000a0, 0x00000010, 0x000000ae, 0x0000000a,
	0x000000be, 0x00000008, 0x000000c8, 0x00000006, 0x000000d0,
	0x0000000a, 0x000000d6, 0x0000000c, 0x000000e0, 0x0000000c,
	0x000000ec, 0x0000000e, 0x000000f8, 0x00000010, 0x00000106,
	0x0000000e, 0x00000116, 0x00000004, 0x00000124
]
secret = [
	0xb8, 0xea, 0x8e, 0xba, 0x3a, 0x88, 0xae, 0x8e, 0xe8, 0xaa,
	0x28, 0xbb, 0xb8, 0xeb, 0x8b, 0xa8, 0xee, 0x3a, 0x3b, 0xb8,
	0xbb, 0xa3, 0xba, 0xe2, 0xe8, 0xa8, 0xe2, 0xb8, 0xab, 0x8b,
	0xb8, 0xea, 0xe3, 0xae, 0xe3, 0xba, 0x80
]

buffChar = 0
remain = 7

def getValue(byte):
	weird1 = (byte + (7 if byte<0 else 0)) >> 3 # === // 8
	weird2 = byte & 7 # + edx that tends to be always 0
	secret_byte = secret[weird1] >> (7 - weird2)
	#print(f'\t{hex(weird1)} {hex(weird2)} {hex(secret_byte)}')
	return secret_byte & 1

def fill_the_map():
	the_map = dict()
	print('Dictionary:')
	import string
	for char in string.printable[10:36]+' ':
		seq=''
		byte = ord(char)
		if chr(byte) == ' ':
			byte = ord('{')
		c1 = matrix[(byte-0x61)*2 + 1]
		c2 = matrix[(byte-0x61)*2]
		mtrx_char = c1 + c2
		#print(f'enc {hex(c1)} {hex(c2)} {hex(mtrx_char)}')
		for i in range(c1, mtrx_char):
			seq += str(getValue(i))
		the_map[seq] = char
		print([char], seq)
	return the_map

def read_seq():
	with open('output_flag', 'rb') as f:
		file = f.read()
	seq = ''
	for b in file:
		bs = bin(b)[2:]
		seq += '00000000'[:-len(bs)] + bs
	return seq

the_map = fill_the_map()
seq = read_seq()
print(f'Seq:\n {seq}')

def resemble_flag(flag, remainder):
	if '1' not in remainder:
		return print('Possible flag:', flag)
	for seq in the_map.keys():
		if remainder.startswith(seq):
			char = the_map[seq]
			resemble_flag(flag + char, remainder[len(seq):])

resemble_flag('', seq)
```

### Script output

```bash
Dictionary:
['a'] 10111000
['b'] 111010101000
['c'] 11101011101000
['d'] 1110101000
['e'] 1000
['f'] 101011101000
['g'] 111011101000
['h'] 1010101000
['i'] 101000
['j'] 1011101110111000
['k'] 111010111000
['l'] 101110101000
['m'] 1110111000
['n'] 11101000
['o'] 11101110111000
['p'] 10111011101000
['q'] 1110111010111000
['r'] 1011101000
['s'] 10101000
['t'] 111000
['u'] 1010111000
['v'] 101010111000
['w'] 101110111000
['x'] 11101010111000
['y'] 1110101110111000
['z'] 11101110101000
[' '] 0000
Seq:
 100011101000111010111010001110111011100011101010001000111​‌​
0101000111011101000101110100011100010111011100010111000101​‌​
010001110111000101010111000101110111000100000

Possible flag: encodedgrtwasmvwe
```
