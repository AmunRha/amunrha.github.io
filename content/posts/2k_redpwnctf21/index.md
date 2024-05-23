---
title: "2k | redpwnctf21"
draft: false
date: 2021-03-19
description: "This is a simple VM which has around 25-27 opcodes with instructions simple enough to be emulated. This is a stack based VM."
categories:
  - CTF
  - Reverse Engineering
tags:
  - VM
  - CTF
  - z3
tableOfContents: true
---

## Description

{{< img src="screenshot.png" alt="Screenshot" >}}

Challenge Author: EvilMuffinHa

## Introduction

This is a simple VM which has around 25-27 opcodes with instructions simple enough to be emulated. This is a stack based VM.

The VM implements several constraints on the input bytes which can be solved using z3 SMT solver.

The VM implemented a puzzle called `kenken`

## Solution

I chose python to write the disassembler in with several helper functions, at first I tried extracting the constrains one by one, which eventually worked, but then I was able to write a automatic extractor for the disassembly. 

This when fed to the z3 solution script will get us the required input.

Most of the operations take their operands from the stack, so there wasn't much complexity in terms of implementation.

*p.s. This will be a short write up*

```python
def disasm(op, c):
    if c > dump_len:
        return -1
    ## print(f"\n[{hex(op):<3}]:[{hex(c):<3}]\t")
    ## print("MOV dctr, ctr1+1")
    ## print(op_desc[op]+'\n')
    extract(op,rsp,ctr1)

    dctr = ctr1 + 1
    if op == 0x1:
        rsp.append(rsp[-1])
        ctr1+=1
    elif op == 0x2:
        rsp = rsp[:-1]
        ctr1+=1   
    elif op == 0x3:
        if rsp[-1] == -1:
            rsp = rsp[:-1]
            ctr1+=1
        elif rsp[-1] != 0:
            print(f"[+] RETURN: {rsp[-1]}")
            return -1
        else:
            print("[+] READING FLAG FILE")
            return 1
    elif op == 0x10:
        rsp[-2] = rsp[-1] + rsp[-2]
        rsp = rsp[:-1]
        ctr1+=1    
    elif op == 0x11:
        rsp[-2] = rsp[-1] - rsp[-2]
        rsp = rsp[:-1]
        ctr1+=1   
    elif op == 0x12:
        rsp[-2] = rsp[-1] * rsp[-2]
        rsp = rsp[:-1]
        ctr1+=1     
    elif op == 0x13:
        rsp[-2] = rsp[-1] // rsp[-2]
        rsp = rsp[:-1]
        ctr1+=1    
    elif op == 0x14:
        rsp[-2] = rsp[-1] % rsp[-2]
        rsp = rsp[:-1]
        ctr1+=1   
    elif op == 0x15:
        tmp = rsp[-1]
        rsp.pop(-1)
        res = rsp[-2]*rsp[-1]%tmp
        rsp = rsp[:-2]
        rsp.append(res)
        ctr1 = dctr  
    elif op == 0x16:
        rsp[-2] = 1 if rsp[-1] == rsp[-2] else 0
        ctr1+=1
        rsp = rsp[:-1]    
    elif op == 0x17:
        if rsp[-1] < 0:
            rsp[-1] = -1
        elif rsp[-1] > 0:
            rsp[-1] = 1
        ctr1+=1   
    elif op == 0x20:
        rsp.append(inp[ii])
        ii+=1
        ctr1 = dctr  
    elif op == 0x21:
        v30 = rsp[-1]
        rsp = rsp[:-1]
        ctr1 = dctr
        print(chr(v30))
        output.append(v30) 
    elif op == 0x22:
        ctr1+=3
        rsp.append((f[dctr+1]<<8) | f[dctr]) 
    elif op == 0x30:
        v30 = rsp.pop(-1)
        ctr1 = abs(v30)  
    elif op == 0x31:
        if rsp[-2] != 0:    ##  Adjust/Remove the condition in order to extract
            rsp = rsp[:-2]  ##  all equations with test input
            ctr1+=1         ##  Keep it if using valid input
        else:
            ctr1 = rsp[-1]
            rsp = rsp[:-2]   
    elif op == 0x32:
        if rsp[-2] != 0:     ##  Adjust/Remove the condition in order to extract
            ctr1 = rsp[-1]   ##  all equations with test input
            rsp = rsp[:-2]   ##  Keep it if using valid input
        else:
            rsp = rsp[:-2]
            ctr1+=1   
    elif op == 0x33:
        if rsp[-2] < 0:
            ctr1 = rsp[-1]
            rsp = rsp[:-2]
        else:
            rsp = rsp[:-2]
            ctr1+=1    
    elif op == 0x34:
        if rsp[-2] <= 0:
            rsp = rsp[:-2]
            ctr1+=1
        else:
            ctr1 = rsp[-1]
            rsp = rsp[-2]   
    elif op == 0x35:
        if rsp[-2] > 0:
            rsp = rsp[:-2]
            ctr1+=1
        else:
            ctr1 = rsp[-1]
            rsp = rsp[-2]    
    elif op == 0x36:
        if rsp[-2] >= 0:
            ctr1 = rsp[-1]
            rsp = rsp[:-2]
        else:
            rsp = rsp[:-2]
            ctr1+=1    
    elif op == 0x40:
        v33 = rsp.pop(-1)
        data[v13] = v33
        ctr1 = dctr    
    elif op == 0x41:
        ctr1+=1
        rsp.append(data[v13])   
    elif op == 0x50:
        v13+=1
        ctr1+=1   
    elif op == 0x51:
        v13-=1
        ctr1+=1    
    elif op == 0x52:
        v13 = (rsp[-1]+v13) & 0xff
        ctr1+=1
        rsp = rsp[:-1]    
    elif op == 0x53:
        v13 = (v13 - rsp[-1]) & 0xff
        ctr1+=1
        rsp = rsp[:-1]            
    else:
        print(f"""[!] UNKNOWN OPCODE: {hex(op)}""", end='')
        return -1

    ## print_stack(rsp)
    ## print_data(data)
    ## print_reg(v13,ctr1,dctr,ii)
    return ctr1
```

Commenting the lines specified can get us the extracted constrains.

I wrote a small parser on my disassembly which will get the proper constraints.

```python
equations = {"add_2":[], "add_3":[], "equate_3": [], "equate_4":[], "mod_equate_2":[], "sub_2":[], "equal_2":[]}
def parse(bbl, f):
    PUSH_OPERAND = [0x22, 0x52, 0x41]
    SUB_2 = (16,2)
    EQUATE_3 = (21,3)
    EQUATE_4 = (28,4) 
    ADD_2 = (13,2)
    ADD_3 = (19,3)
    MOD_EQUATE_2 = (64,2)
    EQUAL_2 = (7,2)

    for llist in bbl:
        eq = []
        bbl_len = len(llist)
        i = 1
        while True:
            if i+2 >= bbl_len:
                break
            if [llist[i][0],llist[i+1][0],llist[i+2][0]] == PUSH_OPERAND:
                ctr = llist[i][1]
                res = f[ctr+1]
                eq.append(res)
                i+=3
            i+=1
        ctr = llist[0][1]
        res = [f[ctr+1]]
        if bbl_len == SUB_2[0]:
            eq = eq[:SUB_2[1]] + res
            equations["sub_2"].append(eq)
        elif bbl_len == EQUATE_3[0]:
            eq = eq[:EQUATE_3[1]] + res
            equations["equate_3"].append(eq)
        elif bbl_len == EQUATE_4[0]:
            eq = eq[:EQUATE_4[1]] + res
            equations["equate_4"].append(eq)
        elif bbl_len == ADD_2[0]:
            eq = eq[:ADD_2[1]] + res
            equations["add_2"].append(eq)
        elif bbl_len == ADD_3[0]:
            eq = eq[:ADD_3[1]] + res
            equations["add_3"].append(eq)
        elif bbl_len == MOD_EQUATE_2[0]:
            eq = eq[:MOD_EQUATE_2[1]] + res
            equations["mod_equate_2"].append(eq)
        elif bbl_len == EQUAL_2[0]:
            eq = eq[:EQUAL_2[1]] + res
            equations["equal_2"].append(eq)
    return equations
```

There were in total 8 different constraints applied on the input bytes, which was added to z3.

```python
def set_idx(set_to):
    for i in set_to:
        s.add(f[i[0]] == i[1])

def sub2(s_list):
    for i in s_list:
        s.add(f[i[1]] - f[i[0]] == i[2])

def add2(a2_list):
    for i in a2_list:
        s.add(f[i[0]]+f[i[1]] == i[2])

def add3(a3_list):
    for i in a3_list:
        s.add(f[i[0]]+f[i[1]]+f[i[2]] == i[3])

def equate3(e3_list):
    for i in e3_list:
        res = (f[i[2]]*f[i[1]])%0x7fff
        s.add((f[i[0]]*res)%0x7fff == i[3])

def equate4(e4_list):
    for i in e4_list:
        res = (f[i[3]]*f[i[2]])%0x7fff
        res = (f[i[1]]*res)%0x7fff
        s.add((f[i[0]]*res)%0x7fff == i[4])

def mod_equate2(m2_list):
    for i in m2_list:
        s.add((f[i[1]] % f[i[0]]) * (f[i[0]] % f[i[1]]) == 0)
        s.add(f[i[0]] != f[i[1]]) 
        s.add(UDiv((UDiv(f[i[1]], f[i[0]]) + UDiv(f[i[0]], f[i[1]])),1) == i[2])

def distinct_add():
    for i in off:
        s.add(f[i[0]] != f[i[1]])
```

Running the script gives us the disassembly, and the extracted constraints

{{< img src="output.png" alt="Output.png" >}}

and pasting the extracted constraints to z3, gives us the input to be given,

```
pB738150rHt60714NP501s92420G3xUY013;Wo{=69h42Ob736B1y{@?1047uw`6
```

Sending this over the given nc connection, gives us the flag,

Flag: `flag{kenken_is_just_z3_064c4}`
