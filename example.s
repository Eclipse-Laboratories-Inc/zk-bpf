lddw r1, 0x400000000
ldxw r0,[r1+0]
ldxw r1,[r1+4]
mul32 r0, r1
lddw r1, 0
exit
