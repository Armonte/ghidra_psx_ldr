package psx;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * MIPS Address Pattern Analyzer
 *
 * Detects LUI + ADDIU/ORI instruction patterns and creates cross-references
 * to the computed addresses. This is critical for PSX/System 12 analysis where
 * Ghidra's default analysis doesn't resolve these patterns.
 *
 * Pattern 1: LUI + ADDIU (sign-extended lower)
 *   lui  $reg, 0xHHHH        ; reg = HHHH0000
 *   addiu $reg, $reg, 0xLLLL ; reg = HHHHLLLL (sign-extended)
 *
 * Pattern 2: LUI + ORI (zero-extended lower)
 *   lui $reg, 0xHHHH         ; reg = HHHH0000
 *   ori $reg, $reg, 0xLLLL   ; reg = HHHHLLLL (zero-extended)
 *
 * @author PSX Loader Team
 */
public class MipsAddressAnalyzer extends AbstractAnalyzer {

    private static final String NAME = "MIPS LUI+ADDIU Address References";
    private static final String DESCRIPTION =
        "Analyzes MIPS LUI+ADDIU/ORI instruction patterns to create cross-references " +
        "for computed addresses. Essential for PSX/System 12 disassembly.";

    // Configuration options
    private static final String OPTION_SEARCH_WINDOW = "Instruction Search Window";
    private static final String OPTION_CREATE_LABELS = "Create Labels for Unnamed Targets";
    private static final String OPTION_MIN_ADDRESS = "Minimum Valid Address (hex)";
    private static final String OPTION_MAX_ADDRESS = "Maximum Valid Address (hex)";

    private int searchWindow = 10;  // How many instructions to look ahead for ADDIU/ORI
    private boolean createLabels = false;
    private long minValidAddress = 0x80000000L;  // PSX RAM start
    private long maxValidAddress = 0x80800000L;  // 8MB (System 12 max)

    private static final int NOTIFICATION_INTERVAL = 1024;

    // Statistics
    private int refsCreated = 0;
    private int patternsFound = 0;

    public MipsAddressAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        // Run after basic disassembly but before function analysis
        setPriority(AnalysisPriority.DISASSEMBLY.after());
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor processor = program.getLanguage().getProcessor();
        return processor.equals(Processor.findOrPossiblyCreateProcessor("PSX")) ||
               processor.equals(Processor.findOrPossiblyCreateProcessor("MIPS"));
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPTION_SEARCH_WINDOW, searchWindow, null,
            "Maximum number of instructions to search after LUI for matching ADDIU/ORI");
        options.registerOption(OPTION_CREATE_LABELS, createLabels, null,
            "Create labels for target addresses that don't have one");
        options.registerOption(OPTION_MIN_ADDRESS, String.format("0x%08X", minValidAddress), null,
            "Minimum address to consider valid (hex)");
        options.registerOption(OPTION_MAX_ADDRESS, String.format("0x%08X", maxValidAddress), null,
            "Maximum address to consider valid (hex)");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        searchWindow = options.getInt(OPTION_SEARCH_WINDOW, searchWindow);
        createLabels = options.getBoolean(OPTION_CREATE_LABELS, createLabels);

        try {
            String minStr = options.getString(OPTION_MIN_ADDRESS, String.format("0x%08X", minValidAddress));
            minValidAddress = Long.decode(minStr);
        } catch (NumberFormatException e) {
            // Keep default
        }

        try {
            String maxStr = options.getString(OPTION_MAX_ADDRESS, String.format("0x%08X", maxValidAddress));
            maxValidAddress = Long.decode(maxStr);
        } catch (NumberFormatException e) {
            // Keep default
        }
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {

        refsCreated = 0;
        patternsFound = 0;

        // Remove uninitialized blocks from analysis
        set = removeUninitializedBlocks(program, set);

        Listing listing = program.getListing();
        ReferenceManager refManager = program.getReferenceManager();
        SymbolTable symbolTable = program.getSymbolTable();

        long locationCount = set.getNumAddresses();
        if (locationCount > NOTIFICATION_INTERVAL) {
            monitor.initialize(locationCount);
        }

        monitor.setMessage("Analyzing MIPS LUI+ADDIU patterns...");

        InstructionIterator instructions = listing.getInstructions(set, true);
        int count = 0;

        while (instructions.hasNext()) {
            monitor.checkCancelled();

            Instruction instr = instructions.next();

            if (locationCount > NOTIFICATION_INTERVAL && (count % NOTIFICATION_INTERVAL) == 0) {
                monitor.setProgress(count);
                monitor.setMessage(String.format("Analyzing LUI+ADDIU patterns... (found %d, refs %d)",
                    patternsFound, refsCreated));
            }
            count++;

            // Check if this is a LUI instruction
            if (!isLuiInstruction(instr)) {
                continue;
            }

            // Extract LUI operands: lui $reg, immediate
            Register destReg = getDestinationRegister(instr);
            Long upperValue = getImmediateValue(instr, 1);

            if (destReg == null || upperValue == null) {
                continue;
            }

            // Search forward for ADDIU/ORI that uses this register
            Instruction matchingInstr = findMatchingInstruction(program, instr, destReg, monitor);

            if (matchingInstr != null) {
                Long lowerValue = getImmediateValue(matchingInstr, 2);
                if (lowerValue != null) {
                    // Calculate the full address
                    long fullAddress = computeAddress(upperValue, lowerValue,
                        matchingInstr.getMnemonicString().toLowerCase().contains("addiu"));

                    // Validate address is in expected range
                    if (fullAddress >= minValidAddress && fullAddress < maxValidAddress) {
                        patternsFound++;

                        // Create reference from the ADDIU/ORI instruction to the computed address
                        Address targetAddr = program.getAddressFactory()
                            .getDefaultAddressSpace().getAddress(fullAddress);

                        // Check if memory exists at target
                        if (program.getMemory().contains(targetAddr)) {
                            // Check if reference already exists
                            Reference[] existingRefs = refManager.getReferencesFrom(matchingInstr.getAddress());
                            boolean refExists = false;
                            for (Reference ref : existingRefs) {
                                if (ref.getToAddress().equals(targetAddr)) {
                                    refExists = true;
                                    break;
                                }
                            }

                            if (!refExists) {
                                // Create the reference
                                refManager.addMemoryReference(
                                    matchingInstr.getAddress(),  // From address (the ADDIU/ORI)
                                    targetAddr,                   // To address (computed target)
                                    RefType.DATA,                 // Reference type
                                    SourceType.ANALYSIS,          // Source type
                                    0                             // Operand index
                                );
                                refsCreated++;

                                // Optionally create a label if none exists
                                if (createLabels) {
                                    Symbol[] symbols = symbolTable.getSymbols(targetAddr);
                                    if (symbols.length == 0) {
                                        try {
                                            String labelName = String.format("DAT_%08X", fullAddress);
                                            symbolTable.createLabel(targetAddr, labelName, SourceType.ANALYSIS);
                                        } catch (Exception e) {
                                            // Label creation failed, not critical
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Only log if something was found (avoid cluttering the log)
        if (patternsFound > 0 || refsCreated > 0) {
            log.appendMsg(NAME, String.format("Analysis complete: Found %d LUI+ADDIU/ORI patterns, created %d references",
                patternsFound, refsCreated));
        }

        return true;
    }

    /**
     * Check if instruction is a LUI instruction
     */
    private boolean isLuiInstruction(Instruction instr) {
        String mnemonic = instr.getMnemonicString().toLowerCase();
        return mnemonic.equals("lui") || mnemonic.equals("_lui");
    }

    /**
     * Check if instruction is ADDIU or ORI
     */
    private boolean isAddiuOrOri(Instruction instr) {
        String mnemonic = instr.getMnemonicString().toLowerCase();
        return mnemonic.equals("addiu") || mnemonic.equals("_addiu") ||
               mnemonic.equals("ori") || mnemonic.equals("_ori");
    }

    /**
     * Get destination register from instruction (operand 0)
     */
    private Register getDestinationRegister(Instruction instr) {
        Object[] objs = instr.getOpObjects(0);
        if (objs.length > 0 && objs[0] instanceof Register) {
            return (Register) objs[0];
        }
        return null;
    }

    /**
     * Get source register from instruction (operand 1 for ADDIU/ORI)
     */
    private Register getSourceRegister(Instruction instr, int operandIndex) {
        Object[] objs = instr.getOpObjects(operandIndex);
        if (objs != null) {
            for (Object obj : objs) {
                if (obj instanceof Register) {
                    return (Register) obj;
                }
            }
        }
        return null;
    }

    /**
     * Get immediate value from instruction operand
     */
    private Long getImmediateValue(Instruction instr, int operandIndex) {
        Object[] objs = instr.getOpObjects(operandIndex);
        if (objs != null) {
            for (Object obj : objs) {
                if (obj instanceof Scalar) {
                    return ((Scalar) obj).getValue();
                }
            }
        }
        return null;
    }

    /**
     * Search forward from LUI to find matching ADDIU/ORI
     */
    private Instruction findMatchingInstruction(Program program, Instruction luiInstr,
            Register targetReg, TaskMonitor monitor) {

        Instruction current = luiInstr;

        for (int i = 0; i < searchWindow; i++) {
            // Get next instruction
            current = current.getNext();
            if (current == null) {
                return null;
            }

            // Check if this instruction overwrites the target register with something other than ADDIU/ORI
            Register destReg = getDestinationRegister(current);
            if (destReg != null && destReg.equals(targetReg)) {
                // This instruction writes to our target register
                if (isAddiuOrOri(current)) {
                    // Check if source register matches (ADDIU/ORI $reg, $reg, imm)
                    Register srcReg = getSourceRegister(current, 1);
                    if (srcReg != null && srcReg.equals(targetReg)) {
                        return current;
                    }
                }
                // Register overwritten by something else, stop searching
                return null;
            }

            // Check if we hit a branch/jump that might invalidate our tracking
            if (current.getFlowType().isJump() || current.getFlowType().isCall()) {
                // Could still be in delay slot, continue one more
                if (i < searchWindow - 1) {
                    continue;
                }
                return null;
            }
        }

        return null;
    }

    /**
     * Compute full 32-bit address from LUI upper value and ADDIU/ORI lower value
     *
     * For ADDIU: The immediate is sign-extended, so if bit 15 is set,
     * the upper value needs adjustment.
     *
     * For ORI: The immediate is zero-extended, straightforward combination.
     */
    private long computeAddress(long upperValue, long lowerValue, boolean isAddiu) {
        if (isAddiu) {
            // ADDIU sign-extends the immediate
            // If lower 16 bits have bit 15 set, it's negative when sign-extended
            short signedLower = (short)(lowerValue & 0xFFFF);
            return ((upperValue & 0xFFFF) << 16) + signedLower;
        } else {
            // ORI zero-extends
            return ((upperValue & 0xFFFF) << 16) | (lowerValue & 0xFFFF);
        }
    }

    /**
     * Remove uninitialized memory blocks from the address set
     */
    private AddressSetView removeUninitializedBlocks(Program program, AddressSetView set) {
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        AddressSet result = new AddressSet(set);

        for (MemoryBlock block : blocks) {
            if (!block.isInitialized() || !block.isLoaded()) {
                result.delete(new AddressRangeImpl(block.getStart(), block.getEnd()));
            }
        }

        return result;
    }
}
