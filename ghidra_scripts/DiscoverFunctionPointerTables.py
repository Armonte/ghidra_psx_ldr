# -*- coding: utf-8 -*-
#@author Arika Games Research
#@category Analysis
#@keybinding
#@menupath Tools.Analysis.Discover Function Pointer Tables
#@toolbar
# Script to automatically discover function pointer tables by scanning memory
# for regions containing many valid function addresses

from ghidra.program.flatapi import FlatProgramAPI

api = FlatProgramAPI(currentProgram)
addrFactory = api.getAddressFactory()
funcManager = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()

def read_pointer_at_address(addr):
    """Read a 32-bit pointer from memory at the given address (big-endian)"""
    try:
        if not memory.contains(addr):
            return None
        
        bytes_array = bytearray(4)
        memory.getBytes(addr, bytes_array)
        
        # Big-endian: MSB first
        pointer = (bytes_array[0] << 24) | (bytes_array[1] << 16) | (bytes_array[2] << 8) | bytes_array[3]
        return pointer
    except:
        return None

def is_valid_function_address(addr_value):
    """Check if address points to a function"""
    # PSX RAM range: 0x80000000 - 0x803fffff
    if addr_value < 0x80000000 or addr_value > 0x803fffff:
        return False
    
    try:
        addr = addrFactory.getAddress("0x{:08x}".format(addr_value))
        if addr is None:
            return False
        
        func = funcManager.getFunctionContaining(addr)
        if func is None:
            func = funcManager.getFunctionAt(addr)
        
        return func is not None
    except:
        return False

def scan_region_for_function_pointers(start_addr, length, min_entries=5):
    """Scan a memory region for function pointer tables"""
    found_tables = []
    entry_size = 4  # 32-bit pointers
    max_entries = length // entry_size
    
    consecutive_valid = 0
    table_start = None
    table_entries = []
    
    for i in range(max_entries):
        entry_addr = start_addr.add(i * entry_size)
        pointer_value = read_pointer_at_address(entry_addr)
        
        if pointer_value and is_valid_function_address(pointer_value):
            if table_start is None:
                table_start = entry_addr
            consecutive_valid += 1
            table_entries.append({
                "index": i,
                "addr": entry_addr,
                "pointer": pointer_value
            })
        else:
            # End of potential table
            if consecutive_valid >= min_entries:
                # Found a table!
                found_tables.append({
                    "start_addr": table_start,
                    "end_addr": entry_addr.subtract(entry_size),
                    "entry_count": consecutive_valid,
                    "entries": table_entries[:]
                })
            
            consecutive_valid = 0
            table_start = None
            table_entries = []
    
    # Check if table extends to end of region
    if consecutive_valid >= min_entries:
        found_tables.append({
            "start_addr": table_start,
            "end_addr": start_addr.add((max_entries - 1) * entry_size),
            "entry_count": consecutive_valid,
            "entries": table_entries[:]
        })
    
    return found_tables

def main():
    print("=" * 80)
    print("FUNCTION POINTER TABLE DISCOVERY")
    print("=" * 80)
    print("\nScanning memory for function pointer tables...")
    print("Looking for regions with 5+ consecutive valid function pointers\n")
    
    # Known regions to scan (PSX RAM: 0x80000000 - 0x803fffff)
    scan_regions = [
        ("0x80100000-0x8011ffff", 0x80100000, 0x20000),  # 0x8010xxxx and 0x8011xxxx
        ("0x801d0000-0x801dffff", 0x801d0000, 0x10000),  # Known table region
        ("0x80200000-0x8021ffff", 0x80200000, 0x20000),  # 0x8020xxxx and 0x8021xxxx
    ]
    
    all_tables = []
    
    for region_name, start, length in scan_regions:
        print("Scanning {}...".format(region_name))
        try:
            start_addr = addrFactory.getAddress("0x{:08x}".format(start))
            if start_addr is None:
                print("  Invalid address: 0x{:08x}".format(start))
                continue
            
            tables = scan_region_for_function_pointers(start_addr, length, min_entries=5)
            if tables:
                print("  Found {} table(s)".format(len(tables)))
                all_tables.extend(tables)
            else:
                print("  No tables found")
        except Exception as e:
            print("  Error scanning {}: {}".format(region_name, e))
    
    print("\n" + "=" * 80)
    print("DISCOVERED FUNCTION POINTER TABLES")
    print("=" * 80)
    
    if not all_tables:
        print("\nNo function pointer tables found.")
        print("Try:")
        print("  1. Check if you're analyzing the correct binary")
        print("  2. Verify functions are defined in Ghidra")
        print("  3. Adjust scan regions or min_entries threshold")
        return
    
    for i, table in enumerate(all_tables, 1):
        print("\nTable {}:".format(i))
        print("  Address: {} - {}".format(table["start_addr"], table["end_addr"]))
        print("  Entries: {}".format(table["entry_count"]))
        print("  First 5 function pointers:")
        for entry in table["entries"][:5]:
            try:
                func_addr = addrFactory.getAddress("0x{:08x}".format(entry["pointer"]))
                func = funcManager.getFunctionContaining(func_addr)
                if func is None:
                    func = funcManager.getFunctionAt(func_addr)
                func_name = func.getName() if func else "Unknown"
                print("    [{}]: 0x{:08x} -> {} ({})".format(
                    entry["index"], entry["pointer"], func_name, func_addr))
            except:
                print("    [{}]: 0x{:08x}".format(entry["index"], entry["pointer"]))
    
    print("\n" + "=" * 80)
    print("NEXT STEPS:")
    print("=" * 80)
    print("1. Add discovered tables to FindFunctionPointerXrefs.py")
    print("2. Verify table purposes by analyzing function names")
    print("3. Check if tables are accessed via computed addressing")

if __name__ == "__main__":
    main()



