class LibraryDict:

  libraryDict = dict()
  read_str = '000 121 000 0a0 111 000 0c4 158 000 080 000 000 - 060 172 000 000 182 008 000 120 000 000 140 108 070 080 148 158 000 1ac 000 0d0 18a 000 040 023 - 170 000 182 031 00c 0d0 020 0c6 010'

  puts_str = '03a 168 010 000 000 000 13a 16b 050 000 000 000 - 13b 063 1a1 17a 013 063 03a 169 070 000 000 000 038 159 000 000 000 048 100 124 000 090 151 000 - 000 000 000 1d4 140 140 094 051 141 100 180 02b 000 125 148 000 115 01a 050 150 000 000 000 000'

  atoi_str = '13a 16b 050 000 000 000 13b 063 1a1 17a 013 04b - 03a 169 070 000 000 000 100 120 000 000 121 000 000 151 000 000 000 000 1d0 140 100 100 172 020 - 000 180 00c 000 001 00b 010 060 101 1ff 187 1eb 000 151 000 000 000 000 1d0 140 100 100 172 02d - 100 180 018 000 151 000 000 000 000 1d0 140 100 100 172 02b 100 180 009 100 121 000 100 187 009 - 000 124 001 0d0 060 101 0c6 050 061 100 180 027 0c0 060 001 000 061 001 050 001 00b 012 060 121 - 006 151 000 000 000 000 1d0 140 100 100 172 02d'

  fflush_str = '03a 168 010 000 000 000 13a 16b 050 000 000 000 - 13b 063 1a1 17a 013 033 03a 169 050 000 000 000 038 159 000 000 000 048 050 159 000 000 000 000 - 120 172 000 100 186 009 000 120 000 100 187 036'

  printf_str = '03a 168 0f0 000 000 000 13a 16b 050 000 000 000 - 13b 063 1a1 17a 013 07b 03a 169 070 000 000 000 038 001 063 100 124 148 100 114 01a 078 158 000 - 000 000 048 012 158 000 000 000 000 090 060 101 1ff 1c8 1fd 02b 040 061 001 000 125 000 014 061 - 141 012 060 121 03a 159 068 000 000 000 138 15b'

  exit_str = '03a 168 010 000 000 000 13a 16b 050 000 000 000 - 13b 063 1a1 17a 013 01b 03a 169 010 000 000 000 038 159 000 000 000 048 1ff 1c8 1ff 188 010 060 - 101 000 1c8 005 010 000 120 000 03a 159 008 000 000 000 138 15b 040 000 000 000 17a 003 01b 000 - 140 13a 16b 050 000 000 000 13b 063 1a1 17a 013'

  write_str = '102 060 020 000 121 000 0a0 111 040 0c4 158 000 - 080 000 000 060 172 000 100 180 008 080 140 1ff 187 1f2 10f 121 1ff 023 170 000 182 011 080 0d0 - 020 044 168 000 080 000 000 008 060 080 000 140 080 0d0 060 000 000 060 0c4 168 000 080 000 000 - 042 010 060 1ff 187 1ca 0c0 140 0c0 140 000 172'

  memset_str = '0c0 060 000 102 100 048 048 060 020 102 100 048 - 048 060 020 040 172 003 000 185 00f 046 168 008 000 000 000 084 010 01a 1ff 187 1f1 040 172 001 - 000 181 015 000 182 00c 046 160 000 000 000 000'

  def str_to_byte_arr(self, s):
    s = s.replace(' - ', ' ')
    byte_arr = []

    for byte in s.split(' '):
      byte_arr.append(int(byte, 16))

    return byte_arr

  def __init__(self):
    self.addLibrary('read', self.read_str)
    self.addLibrary('write', self.write_str)
    self.addLibrary('exit', self.exit_str)
    self.addLibrary('puts', self.puts_str)
    self.addLibrary('printf', self.printf_str)
    self.addLibrary('fflush', self.fflush_str)
    self.addLibrary('atoi', self.atoi_str)
    self.addLibrary('memset', self.memset_str)

  def addLibrary(self, name, s):
    self.libraryDict[name] = self.str_to_byte_arr(s)

  def __getitem__(self, k):
    return self.libraryDict[k]

  def getDict(self):
    return self.libraryDict