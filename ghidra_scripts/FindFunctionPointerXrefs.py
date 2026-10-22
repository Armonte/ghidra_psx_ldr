# -*- coding: utf-8 -*-
#@author Arika Games Research
#@category Reference
#@keybinding
#@menupath Tools.References.Find Function Pointer XRefs
#@toolbar
# Script to find and create references for functions called via function pointer tables
# This fixes the issue where functions show zero xrefs because they're called indirectly

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import RefType
from ghidra.program.model.symbol import ReferenceManager
from ghidra.program.model.listing import Data
from ghidra.program.model.mem import MemoryAccessException

api = FlatProgramAPI(currentProgram)
refManager = currentProgram.getReferenceManager()
addrFactory = api.getAddressFactory()

# Known function pointer tables
FUNCTION_POINTER_TABLES = [
    {
        "name": "g_CharacterStateInitTable",
        "address": "0x801d8354",
        "entry_size": 4,  # 32-bit pointers
        "entry_count": 38,
        "description": "Character state initialization functions"
    },
    {
        "name": "g_CharacterStateUpdateTable",
        "address": "0x801d82c0",
        "entry_size": 4,
        "entry_count": 38,
        "description": "Character state update functions (per-frame)"
    },
    # Function pointer tables in 0x8011xxxx region (accessed via computed addressing)
    {
        "name": "g_FunctionPointerTable_80110000",
        "address": "0x80110000",
        "entry_size": 4,
        "entry_count": 50,  # Approximate - adjust as needed
        "description": "Function pointer table at 0x80110000 (accessed via LUI+ADDIU)"
    },
    # Add more tables as discovered
    # {
    #     "name": "g_CharacterCallbackTableArray",
    #     "address": "TBD",
    #     "entry_size": 4,
    #     "entry_count": 0,  # Variable per character
    #     "description": "Character-specific callback tables"
    # },
]

def read_pointer_at_address(addr):
    """Read a 32-bit pointer from memory at the given address (big-endian)
    
    MIPS stores addresses in big-endian format:
    Address 0x80250a18 stored as bytes: [0x80, 0x25, 0x0a, 0x18]
    """
    try:
        # MIPS is big-endian, so read 4 bytes and interpret as big-endian
        memory = currentProgram.getMemory()
        if not memory.contains(addr):
            return None
        
        bytes_array = bytearray(4)
        memory.getBytes(addr, bytes_array)
        
        # Big-endian: MSB first
        # bytes_array[0] = most significant byte
        pointer = (bytes_array[0] << 24) | (bytes_array[1] << 16) | (bytes_array[2] << 8) | bytes_array[3]
        return pointer
    except MemoryAccessException:
        return None

def get_function_at_address(addr):
    """Get function at address if it exists"""
    funcManager = currentProgram.getFunctionManager()
    func = funcManager.getFunctionContaining(addr)
    if func is None:
        # Check if address is a function entry point
        func = funcManager.getFunctionAt(addr)
    return func

def create_data_reference(from_addr, to_addr, ref_type_name="DATA"):
    """Create a data reference from table entry to function"""
    try:
        # Get or create data at the table entry
        data = api.getDataAt(from_addr)
        if data is None:
            # Create pointer data if it doesn't exist
            # Use PointerDataType for 32-bit pointers
            from ghidra.program.model.data import PointerDataType
            pointer_type = PointerDataType.dataType
            data = api.createData(from_addr, pointer_type)
            if data is None:
                print("Failed to create data at {}".format(from_addr))
                return False
        
        # Get reference type
        refType = RefType.getRefType(ref_type_name)
        if refType is None:
            refType = RefType.DATA  # Default to DATA if name not found
        
        # Check if reference already exists
        existing_refs = refManager.getReferencesFrom(from_addr)
        for ref in existing_refs:
            if ref.getToAddress() == to_addr:
                return False  # Reference already exists
        
        # Create the reference
        ref = api.createMemoryReference(data, to_addr, refType)
        if ref is not None:
            api.setReferencePrimary(ref)
            return True
        else:
            print("Failed to create reference from {} to {}".format(from_addr, to_addr))
            return False
    except Exception as e:
        print("Error creating reference at {}: {}".format(from_addr, e))
        import traceback
        traceback.print_exc()
        return False

def search_table_for_function(table_info, target_func_addr):
    """Search a function pointer table for a specific function address"""
    table_addr = addrFactory.getAddress(table_info["address"])
    if table_addr is None:
        print("Invalid table address: {}".format(table_info["address"]))
        return []
    
    found_entries = []
    entry_size = table_info["entry_size"]
    entry_count = table_info["entry_count"]
    
    print("Searching {} ({} entries at {})...".format(
        table_info["name"], entry_count, table_info["address"]))
    
    # Get target address as integer for comparison
    target_addr_int = int(str(target_func_addr), 16)
    target_upper = (target_addr_int >> 16) & 0xFFFF
    target_lower = target_addr_int & 0xFFFF
    
    for i in range(entry_count):
        entry_addr = table_addr.add(i * entry_size)
        pointer_value = read_pointer_at_address(entry_addr)
        
        if pointer_value is None:
            continue
        
        # Convert to address
        try:
            pointer_addr = addrFactory.getAddress("0x{:08x}".format(pointer_value))
            if pointer_addr is None:
                continue
            
            # Check if this pointer matches our target function
            if pointer_addr == target_func_addr:
                found_entries.append({
                    "table": table_info["name"],
                    "index": i,
                    "table_addr": entry_addr,
                    "function_addr": pointer_addr,
                    "description": "{}[{}]".format(table_info["name"], i),
                    "type": "direct_pointer"
                })
        except Exception:
            continue
    
    return found_entries

def search_computed_addresses_for_function(target_func_addr):
    """Search for LUI+ADDIU patterns that construct the target function address"""
    from ghidra.program.model.scalar import Scalar
    from ghidra.program.model.listing import Instruction
    
    listing = currentProgram.getListing()
    found_patterns = []
    
    # Get target address components
    target_addr_int = int(str(target_func_addr), 16)
    target_upper = (target_addr_int >> 16) & 0xFFFF
    target_lower = target_addr_int & 0xFFFF
    
    # Handle sign extension for lower 16 bits (ADDIU uses signed immediate)
    if target_lower >= 0x8000:
        # Negative value, need to adjust upper
        target_upper_adj = (target_upper + 1) & 0xFFFF
        target_lower_signed = target_lower - 0x10000
    else:
        target_upper_adj = target_upper
        target_lower_signed = target_lower
    
    print("Searching for computed address patterns...")
    print("  Target: {} (upper: 0x{:04x}, lower: 0x{:04x})".format(
        target_func_addr, target_upper, target_lower))
    if target_upper != target_upper_adj:
        print("  Adjusted upper (for negative lower): 0x{:04x}".format(target_upper_adj))
    
    # Search for LUI instructions with matching upper bits
    instruction_iter = listing.getInstructions(True)
    lui_count = 0
    checked_count = 0
    
    for instr in instruction_iter:
        mnemonic = instr.getMnemonicString()
        
        if mnemonic == "lui":
            lui_count += 1
            if lui_count > 10000:  # Limit search to avoid timeout
                break
            
            # Get the immediate value
            num_operands = instr.getNumOperands()
            if num_operands >= 2:
                op1 = instr.getOpObjects(1)
                if op1 and len(op1) > 0:
                    val = op1[0]
                    if isinstance(val, Scalar):
                        upper_val = val.getUnsignedValue() & 0xFFFF
                        
                        # Check if this matches our target upper bits (or adjusted)
                        if upper_val == target_upper or upper_val == target_upper_adj:
                            checked_count += 1
                            # Check next instruction for ADDIU/ORI
                            next_instr = instr.getNext()
                            if next_instr:
                                next_mnemonic = next_instr.getMnemonicString()
                                if next_mnemonic in ["addiu", "ori"]:
                                    # Get the immediate from next instruction
                                    # ADDIU/ORI format: addiu rt, rs, immediate
                                    # Operands: [0]=rt, [1]=rs, [2]=immediate
                                    next_ops = next_instr.getOpObjects(2)  # Immediate is operand 2
                                    if next_ops and len(next_ops) > 0:
                                        next_val = next_ops[0]
                                        if isinstance(next_val, Scalar):
                                            lower_val = next_val.getUnsignedValue() & 0xFFFF
                                            
                                            # Check if this constructs our target address
                                            if next_mnemonic == "addiu":
                                                # ADDIU sign-extends, so check signed value
                                                if lower_val >= 0x8000:
                                                    lower_signed = lower_val - 0x10000
                                                else:
                                                    lower_signed = lower_val
                                                
                                                computed_addr = (upper_val << 16) + lower_signed
                                            else:  # ORI
                                                computed_addr = (upper_val << 16) | lower_val
                                            
                                            if computed_addr == target_addr_int:
                                                func = getFunctionContaining(instr.getAddress())
                                                func_name = func.getName() if func else "Unknown"
                                                found_patterns.append({
                                                    "type": "computed_address",
                                                    "lui_addr": instr.getAddress(),
                                                    "addiu_addr": next_instr.getAddress(),
                                                    "function": func_name,
                                                    "description": "LUI+{} pattern in {}".format(
                                                        next_mnemonic.upper(), func_name)
                                                })
    
    if lui_count > 0:
        print("  Scanned {} LUI instructions, checked {} with matching upper bits".format(
            lui_count, checked_count))
    
    return found_patterns

def find_and_create_xrefs_for_function(func_addr):
    """Find function in all known tables and create references"""
    func = get_function_at_address(func_addr)
    if func is None:
        print("No function found at {}".format(func_addr))
        return []
    
    func_name = func.getName()
    print("\n=== Searching for function: {} ({}) ===".format(func_name, func_addr))
    
    all_found = []
    
    # Search all known tables
    for table_info in FUNCTION_POINTER_TABLES:
        found_entries = search_table_for_function(table_info, func_addr)
        
        for entry in found_entries:
            # Create data reference from table entry to function
            success = create_data_reference(entry["table_addr"], func_addr, "DATA")
            if success:
                print("  [OK] Created reference: {} -> {}".format(
                    entry["description"], func_name))
                all_found.append(entry)
            else:
                print("  [-] Reference already exists: {}".format(entry["description"]))
                all_found.append(entry)
    
    # Also search for computed address patterns (LUI + ADDIU/ORI)
    # Note: This can be slow for large programs - searches all LUI instructions
    print("\nSearching for computed address patterns (LUI + ADDIU/ORI)...")
    computed_patterns = search_computed_addresses_for_function(func_addr)
    if computed_patterns:
        print("  [OK] Found {} computed address pattern(s):".format(len(computed_patterns)))
        for pattern in computed_patterns:
            print("    - {} at {}".format(pattern["description"], pattern["lui_addr"]))
            # Note: Can't create references for computed addresses easily
            # They're constructed at runtime, not stored as data
            all_found.append(pattern)
    
    if not all_found:
        print("  [X] Function not found in any known function pointer tables")
        print("  [X] No computed address patterns found (LUI+ADDIU/ORI)")
        print("\n  Note: Function may be:")
        print("    - Called directly (not via pointer)")
        print("    - In an unknown function pointer table")
        print("    - Accessed via register-based indirect call")
        print("\n  Tip: Check 0x8011xxxx region for function pointer tables")
        print("       (accessed via computed addressing - LUI 0x8011 + ADDIU)")
    
    return all_found

def find_all_functions_in_tables():
    """Find all functions that appear in function pointer tables"""
    print("=== Scanning all function pointer tables ===\n")
    
    all_functions = {}
    
    for table_info in FUNCTION_POINTER_TABLES:
        table_addr = addrFactory.getAddress(table_info["address"])
        if table_addr is None:
            print("Skipping invalid table: {}".format(table_info["address"]))
            continue
        
        print("Scanning {}...".format(table_info["name"]))
        entry_size = table_info["entry_size"]
        entry_count = table_info["entry_count"]
        
        found_in_table = 0
        for i in range(entry_count):
            entry_addr = table_addr.add(i * entry_size)
            pointer_value = read_pointer_at_address(entry_addr)
            
            if pointer_value is None:
                continue
            
            try:
                pointer_addr = addrFactory.getAddress("0x{:08x}".format(pointer_value))
                if pointer_addr is None:
                    continue
                
                # Check if address is in valid range (0x80000000 - 0x803fffff for PSX RAM)
                if pointer_value < 0x80000000 or pointer_value > 0x803fffff:
                    continue
                
                func = get_function_at_address(pointer_addr)
                if func is not None:
                    found_in_table += 1
                    func_addr_str = func.getEntryPoint().toString()
                    if func_addr_str not in all_functions:
                        all_functions[func_addr_str] = {
                            "function": func,
                            "references": []
                        }
                    
                    all_functions[func_addr_str]["references"].append({
                        "table": table_info["name"],
                        "index": i,
                        "table_addr": entry_addr,
                        "description": "{}[{}]".format(table_info["name"], i)
                    })
            except Exception as e:
                # Debug: print first few errors
                if i < 3:
                    print("  Debug entry[{}]: pointer=0x{:08x}, error={}".format(i, pointer_value, e))
                continue
        
        if found_in_table == 0:
            # Debug: show first few entries
            print("  Debug: No functions found. First 3 entries:")
            for i in range(min(3, entry_count)):
                entry_addr = table_addr.add(i * entry_size)
                pointer_value = read_pointer_at_address(entry_addr)
                if pointer_value:
                    print("    [{}]: 0x{:08x} at {}".format(i, pointer_value, entry_addr))
    
    return all_functions

def main():
    """Main function - can be run on current selection or all functions"""
    
    # Check if user has a function selected
    current_addr = currentLocation.getAddress()
    if current_addr is not None:
        func = get_function_at_address(current_addr)
        if func is not None:
            # User has a function selected - search for just this one
            print("Function selected: {} ({})".format(func.getName(), func.getEntryPoint()))
            print("Searching function pointer tables...\n")
            found = find_and_create_xrefs_for_function(func.getEntryPoint())
            
            if found:
                print("\n=== Summary ===")
                print("Found function in {} table(s):".format(len(found)))
                for entry in found:
                    print("  - {}".format(entry["description"]))
            else:
                print("\nFunction not found in any known tables.")
                print("It may be in an unknown table or called directly.")
            return
    
    # No function selected - scan all tables and create references
    print("No function selected. Scanning all function pointer tables...\n")
    
    all_functions = find_all_functions_in_tables()
    
    print("\n=== Summary ===")
    print("Found {} unique functions in function pointer tables".format(len(all_functions)))
    
    created_count = 0
    existing_count = 0
    
    for func_addr_str, func_info in all_functions.items():
        func = func_info["function"]
        for ref_info in func_info["references"]:
            success = create_data_reference(ref_info["table_addr"], func.getEntryPoint(), "DATA")
            if success:
                created_count += 1
            else:
                existing_count += 1
    
    print("Created {} new references".format(created_count))
    print("{} references already existed".format(existing_count))
    print("\nDone!")

if __name__ == "__main__":
    main()

