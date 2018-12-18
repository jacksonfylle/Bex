# Bex
This example is using Triton to Trace and symbolized inputs. At the end of each trace it is trying to find new inputs that may create a different trace, to get a high code coverage.
If Triton cannot find a different path, and if some branch or still untrace, it can asked the help of a Fuzzer to generate/mutate previous inputs.

# Requierements
+ Triton
+ pwntools
+ radamsa
+ termcolor

## Todo
+ [ ] Add multiprocess
+ [ ] possibility to add sevral callback
+ [ ] add the strategy, maximized the symbolic variable number per inputs. Set a bigger default value ? What about loops ?
+ [ ] Concretize everything in the fuzzer
+ [ ] Tracer, multiprocess log only if neeeded

## test
```
python2.7 commands.py
```

## Example output
```bash
dst_addr : 0x0, is_taken : True, unreach : False, fuzz : False, copy_from : 0x0
dst_addr : 0x4011ad, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
            symvarAddress :  0x20010004 values :  o
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
    callAddr :  0x401198
        base_addr 0x9fffff00
            symvarAddress :  0x9fffff01 values :  y
dst_addr : 0x4011ba, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
            symvarAddress :  0x20010004 values :  o
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
    callAddr :  0x401198
        base_addr 0x9fffff00
            symvarAddress :  0x9fffff00 values :  z
            symvarAddress :  0x9fffff01 values :  y
dst_addr : 0x4011c6, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4011ad
dst_addr : 0x4011cb, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4013e9
dst_addr : 0x4011d2, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4011ba
dst_addr : 0x401202, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401303
dst_addr : 0x40124c, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
            symvarAddress :  0x20010003 values :  z
    callAddr :  0x4012dd
        base_addr 0x9fffff80
            symvarAddress :  0x9fffff80 values :  2
            symvarAddress :  0x9fffff81 values :  0
            symvarAddress :  0x9fffff82 values :  4
dst_addr : 0x40125a, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401303
dst_addr : 0x40125f, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401303
dst_addr : 0x40126e, is_taken : True, unreach : False, fuzz : False, copy_from : 0x40124c
dst_addr : 0x4012a0, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010001 values :  u
dst_addr : 0x4012b0, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
dst_addr : 0x4012c1, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
dst_addr : 0x4012f2, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
    callAddr :  0x4012dd
        base_addr 0x9fffff80
            symvarAddress :  0x9fffff80 values :  2
            symvarAddress :  0x9fffff81 values :  0
            symvarAddress :  0x9fffff82 values :  4
dst_addr : 0x401303, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
            symvarAddress :  0x20010003 values :  z
    callAddr :  0x4012dd
        base_addr 0x9fffff80
            symvarAddress :  0x9fffff80 values :  2
            symvarAddress :  0x9fffff81 values :  0
            symvarAddress :  0x9fffff82 values :  4
dst_addr : 0x401337, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20000000
            symvarAddress :  0x20000000 values :  .
            symvarAddress :  0x20000001 values :  /
            symvarAddress :  0x20000002 values :  b
            symvarAddress :  0x20000003 values :  i
            symvarAddress :  0x20000004 values :  n
            symvarAddress :  0x20000005 values :  a
            symvarAddress :  0x20000006 values :  r
            symvarAddress :  0x20000007 values :  y
            symvarAddress :  0x20000008 values :  _
            symvarAddress :  0x20000009 values :  t
            symvarAddress :  0x2000000a values :  e
            symvarAddress :  0x2000000b values :  s
            symvarAddress :  0x2000000c values :  t
            symvarAddress :  0x2000000d values :  /
            symvarAddress :  0x2000000e values :  t
            symvarAddress :  0x2000000f values :  e
            symvarAddress :  0x20000010 values :  s
            symvarAddress :  0x20000011 values :  t
            symvarAddress :  0x20000012 values :  F
            symvarAddress :  0x20000013 values :  u
            symvarAddress :  0x20000014 values :  z
            symvarAddress :  0x20000015 values :  z
            symvarAddress :  0x20000016 values :  1
            symvarAddress :  0x20000017 values :  0
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
            symvarAddress :  0x20010003 values :  z
    callAddr :  0x4012d1
        base_addr 0x9fffff80
            symvarAddress :  0x9fffff80 values :  2
            symvarAddress :  0x9fffff81 values :  0
            symvarAddress :  0x9fffff82 values :  4
dst_addr : 0x401348, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  z
            symvarAddress :  0x20010003 values :  z
    callAddr :  0x4012dd
        base_addr 0x9fffff80
            symvarAddress :  0x9fffff80 values :  2
            symvarAddress :  0x9fffff81 values :  0
            symvarAddress :  0x9fffff82 values :  4
dst_addr : 0x401354, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401337
dst_addr : 0x401371, is_taken : True, unreach : False, fuzz : False, copy_from : 0x40124c
dst_addr : 0x401376, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4012f2
dst_addr : 0x40137b, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4012c1
dst_addr : 0x401380, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4012b0
dst_addr : 0x401391, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
dst_addr : 0x4013a2, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
dst_addr : 0x4013d8, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
dst_addr : 0x4013e9, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
            symvarAddress :  0x20010004 values :  o
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
dst_addr : 0x4013ee, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4013e9
dst_addr : 0x40141b, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
            symvarAddress :  0x20010004 values :  o
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
    callAddr :  0x401198
        base_addr 0x9fffff00
            symvarAddress :  0x9fffff01 values :  \x86
    callAddr :  0x4013fe
        base_addr 0x9fffff60
            symvarAddress :  0x9fffff61 values :  b
dst_addr : 0x401428, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4010b8
        base_addr 0x20010000
            symvarAddress :  0x20010000 values :  f
            symvarAddress :  0x20010001 values :  u
            symvarAddress :  0x20010002 values :  r
            symvarAddress :  0x20010003 values :  i
            symvarAddress :  0x20010004 values :  o
    callAddr :  0x4013c0
        base_addr 0x30000000
            symvarAddress :  0x30000000 values :  b
    callAddr :  0x401198
        base_addr 0x9fffff00
            symvarAddress :  0x9fffff01 values :  \x86
    callAddr :  0x4013fe
        base_addr 0x9fffff60
            symvarAddress :  0x9fffff61 values :  b
            symvarAddress :  0x9fffff60 values :  a
dst_addr : 0x401433, is_taken : True, unreach : False, fuzz : False, copy_from : 0x40141b
dst_addr : 0x401438, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4013e9
dst_addr : 0x40143d, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4013d8
dst_addr : 0x401442, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4013a2
dst_addr : 0x401447, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401391
dst_addr : 0x40144c, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4012b0
dst_addr : 0x401451, is_taken : True, unreach : False, fuzz : False, copy_from : 0x4012a0
dst_addr : 0x401456, is_taken : True, unreach : False, fuzz : False, copy_from : 0x0
dst_addr : 0x40145d, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401428
dst_addr : 0x4014cb, is_taken : True, unreach : False, fuzz : False, copy_from : 0x0
dst_addr : 0x4014e2, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401337
dst_addr : 0x4014fb, is_taken : True, unreach : False, fuzz : False, copy_from : 0x0
dst_addr : 0x40150f, is_taken : True, unreach : False, fuzz : False, copy_from : 0x401337
dst_addr : 0x401348, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x40120a
        loopRound :  0x1 , value :  0xf5
        loopRound :  0x2 , value :  0xf5
        loopRound :  0x3 , value :  0xf5
        loopRound :  0x4 , value :  0xf5
        loopRound :  0x5 , value :  0x68
        loopRound :  0x6 , value :  0xf5
        loopRound :  0x7 , value :  0xf5
        loopRound :  0x8 , value :  0xf5
        loopRound :  0x9 , value :  0xf5
        loopRound :  0xa , value :  0xf5
        loopRound :  0xb , value :  0xf5
        loopRound :  0xc , value :  0xf5
        loopRound :  0xd , value :  0xf5
        loopRound :  0xe , value :  0xf5
        loopRound :  0xf , value :  0xf5
        loopRound :  0x10 , value :  0xf5
        loopRound :  0x11 , value :  0xf5
        loopRound :  0x12 , value :  0xf5
        loopRound :  0x13 , value :  0xf5
        loopRound :  0x14 , value :  0xf5
        loopRound :  0x15 , value :  0xa
    callAddr :  0x401328
        loopRound :  0x1 , value :  0x7
dst_addr : 0x401337, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x4011fa
        loopRound :  0x1 , value :  0x41
    callAddr :  0x40120a
        loopRound :  0x1 , value :  0xef
        loopRound :  0x2 , value :  0xe0
        loopRound :  0x3 , value :  0xb9
        loopRound :  0x4 , value :  0x81
        loopRound :  0x5 , value :  0xb7
        loopRound :  0x6 , value :  0xba
        loopRound :  0x7 , value :  0xf3
        loopRound :  0x8 , value :  0xa0
        loopRound :  0x9 , value :  0x81
        loopRound :  0xa , value :  0xba
        loopRound :  0xb , value :  0xe2
        loopRound :  0xc , value :  0x80
        loopRound :  0xd , value :  0xaf
        loopRound :  0xe , value :  0xa3
        loopRound :  0xf , value :  0xf3
        loopRound :  0x10 , value :  0xa0
        loopRound :  0x11 , value :  0x81
        loopRound :  0x12 , value :  0x8b
        loopRound :  0x13 , value :  0xcd
        loopRound :  0x14 , value :  0x8f
        loopRound :  0x15 , value :  0xa
dst_addr : 0x40124c, is_taken : True, unreach : False, fuzz : False
    callAddr :  0x40120a
        loopRound :  0x1 , value :  0xa
```
