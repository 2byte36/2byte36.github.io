### This readme is for my ctf cheatshits

## Dfir

# chall refs : Bad OPSEC CJ25
Artifacts : Kaspersky.DMP (Mini DuMP crash report)
Used tools : Windbg & bulk_extractor
1. Identify OS + version + computer name
pake `windbg`, 
`!analyze -v` = os + version 
`!peb` = computer name
2. Identify path of the crashed program
`!peb` = ImageFile (the path)
3. Mutex name hunt
- cari start dan end address module program `lm m <program name>` e.g `lm m Kaspersky`
```txt 
start             end                 module name
00000001`40000000 00000001`40050000   Kaspersky   (no symbols)
```
- mutex hunt `s -a <start_addr> <end_addr> "Global\\"` e.g `s -a 0000000140000000 0000000140050000 "Global\\"`
4. i still dont know how to dump the exe file in DMP, so i leave it to the LLM
