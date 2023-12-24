-- MIT License
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
--
-- (C) Author: iomonad <iomonad@riseup.net>
--

local getopt = require('getopt')
local ansicolors = require('ansicolors')

copyright = '(C) 2023 iomonad <iomonad@riseup.net>'
usage = 'script run vigik.lua -k path/to/private_key.pem'
author = 'iomonad'
version = 'v0.0.1'
desc = [[
This script is act like a wrapper around the 'vigik' binary, used to update validity
of a Vigik Service pass.
]]
example = [[
    1. script run vigik.lua -k path/to/private_key.pem -i vigik_pass_dump.bin
]]
usage = [[
script run vigik.lua [-k] [-i]
]]
arguments = [[
    -h              This help
    -k              RSA Private key for the target Vigik Service
    -i              Vigik pass dump
]]

---
-- Usage help
local function help()
   print(copyright)
   print(version)
   print(desc)
   print(ansicolors.cyan..'Usage'..ansicolors.reset)
   print(usage)
   print(ansicolors.cyan..'Arguments'..ansicolors.reset)
   print(arguments)
   print(ansicolors.cyan..'Example usage'..ansicolors.reset)
   print(example)
end

local function oops(err)
    print('[!!] ERROR:', err)
    core.clearCommandBuffer()
    return nil, err
end

local function main(args)
   local generated = os.tmpname()
   local private_key
   local input_dump

   for o, a in getopt.getopt(args, 'hk:i:') do
      if o == 'h' then return help() end
      if o == 'k' then private_key = a end
      if o == 'i' then input_dump = a end
   end

   if private_key == nil or input_dump == nil then
      return help()
   end

   print(('[+] Signing Vigik dump %s with key %s')
      :format(input_dump, private_key))

   local status = os.execute(('vigik sign -q -k %s -i %s -o %s')
      :format(private_key, input_dump, generated))

   if not status == 0 then
      return oops('error while running Vigik binary')
   end

   core.clearCommandBuffer()
   core.console(('hf mf restore --1k --uid deadbeef -k %s')
      :format(generated))
end


main(args)
