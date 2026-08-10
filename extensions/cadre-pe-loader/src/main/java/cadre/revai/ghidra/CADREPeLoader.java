/*
 * CADRE PeLoader — custom Ghidra PE loader based on The Ghidra Book Chapter 17.
 *
 * Problem: Ghidra's stock PeLoader skips or fails to create external references
 * for some PE import tables (empty/packed/binder outer import directories, or
 * import data that is not marked as a pointer). The result is that downstream
 * SQL exporters report an empty `imports` table even though the binary uses many
 * Windows APIs.
 *
 * Fix: subclass the stock PeLoader, delegate the heavy lifting to it, then do a
 * robust second pass over the outer PE's import directory.  For every import
 * descriptor we create pointer data at the IAT slot and add an external
 * reference so the symbol shows up in the `imports` virtual table.  Embedded PEs
 * (common in binders/droppers) are intentionally left to a separate extraction /
 * import step; this loader processes the outer PE image that Ghidra actually
 * maps into memory.
 */
package cadre.revai.ghidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.format.pe.DataDirectory;
import ghidra.app.util.bin.format.pe.ImportByName;
import ghidra.app.util.bin.format.pe.ImportDataDirectory;
import ghidra.app.util.bin.format.pe.ImportDescriptor;
import ghidra.app.util.bin.format.pe.ImportInfo;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.PortableExecutable.SectionLayout;
import ghidra.app.util.bin.format.pe.ThunkData;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.app.util.opinion.LoaderTier;
import ghidra.app.util.opinion.PeLoader;
import ghidra.app.util.opinion.QueryOpinionService;
import ghidra.app.util.opinion.QueryResult;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class CADREPeLoader extends PeLoader {

	public static final String LOADER_NAME = "CADRE PE Loader";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public LoaderTier getTier() {
		return LoaderTier.GENERIC_TARGET_LOADER;
	}

	@Override
	public int getTierPriority() {
		// Lower value = higher priority. Pick something just above the stock PeLoader (50).
		return 49;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		// Re-use the stock PE detection logic, but query opinions using the stock
		// PE loader name so the language/compiler spec is resolved correctly even
		// though our loader has a custom display name.
		List<LoadSpec> loadSpecs = new ArrayList<>();

		if (provider.length() < 4) {
			return loadSpecs;
		}

		PortableExecutable pe = new PortableExecutable(provider, SectionLayout.FILE, false, false);
		NTHeader ntHeader = pe.getNTHeader();
		if (ntHeader != null && ntHeader.getOptionalHeader() != null) {
			long imageBase = ntHeader.getOptionalHeader().getImageBase();
			String machineName = ntHeader.getFileHeader().getMachineName();
			String compilerFamily = PeLoader.CompilerOpinion.getOpinion(pe, provider, null,
				TaskMonitor.DUMMY, new MessageLog()).family;
			for (QueryResult result : QueryOpinionService.query(PeLoader.PE_NAME, machineName,
					compilerFamily)) {
				loadSpecs.add(new LoadSpec(this, imageBase, result));
			}
			if (loadSpecs.isEmpty()) {
				loadSpecs.add(new LoadSpec(this, imageBase, true));
			}
		}

		return loadSpecs;
	}

	@Override
	public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
			ghidra.framework.model.DomainObject domainObject, boolean loadIntoProgram,
			boolean mirrorFsLayout) {
		return super.getDefaultOptions(provider, loadSpec, domainObject, loadIntoProgram,
			mirrorFsLayout);
	}

	@Override
	public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program) {
		return super.validateOptions(provider, loadSpec, options, program);
	}

	@Override
	protected void load(Program program, ImporterSettings settings)
			throws IOException, CancelledException {
		// Let the stock loader do the normal PE loading (memory blocks, headers, exports, etc.).
		super.load(program, settings);

		// The CADRE pipeline imports large, packed, and compound PEs.  Disable the
		// heaviest optional analyzers by default so the headless import does not
		// hang or spend most of its time on features we do not need.
		MessageLog log = settings.log();
		disableHeavyAnalyzers(program, log);

		// Robust pass: make sure every import in the outer PE has pointer data and an
		// ExternalReference, regardless of whether the stock loader marked the IAT slot as a pointer.
		TaskMonitor monitor = settings.monitor();
		monitor.setMessage("CADRE PE Loader: fixing up imports...");
		try {
			fixupImports(program, settings.provider(), log, monitor);
		}
		catch (Exception e) {
			log.appendMsg("CADRE PE Loader: import fixup failed: " + e.getMessage());
			Msg.error(this, "CADRE PE Loader: import fixup failed", e);
		}
	}

	private void disableHeavyAnalyzers(Program program, MessageLog log) {
		Options options = program.getOptions("Analyzers");
		String[] disable = {
			"Decompiler Parameter ID",
			"WindowsPE RTTI Analyzer",
			"Symbolic Propagator"
		};
		for (String name : disable) {
			try {
				options.setBoolean(name, false);
				log.appendMsg("CADRE PE Loader: disabled analyzer: " + name);
			}
			catch (Exception e) {
				log.appendMsg("CADRE PE Loader: could not disable analyzer " + name
					+ ": " + e.getMessage());
			}
		}
	}

	private void fixupImports(Program program, ByteProvider provider, MessageLog log,
			TaskMonitor monitor) throws IOException, CancelledException {

		// Re-parse the file with data directories processed so we can walk the import
		// table ourselves. super.load() already parsed once, but the objects it used
		// are not accessible here.
		PortableExecutable pe = new PortableExecutable(provider, SectionLayout.FILE, true, false);
		NTHeader nt = pe.getNTHeader();
		if (nt == null || nt.getOptionalHeader() == null) {
			log.appendMsg("CADRE PE Loader: no valid NT header, skipping import fixup");
			return;
		}
		processImportDirectory(program, nt.getOptionalHeader(), log, monitor);
	}

	private void processImportDirectory(Program program, OptionalHeader optionalHeader,
			MessageLog log, TaskMonitor monitor) {

		DataDirectory[] dataDirs = optionalHeader.getDataDirectories();
		if (dataDirs == null || dataDirs.length <= OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT) {
			return;
		}
		ImportDataDirectory idd =
			(ImportDataDirectory) dataDirs[OptionalHeader.IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (idd == null) {
			return;
		}
		ImportDescriptor[] descriptors = idd.getImportDescriptors();
		if (descriptors == null || descriptors.length == 0) {
			return;
		}

		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		Listing listing = program.getListing();
		ReferenceManager refMgr = program.getReferenceManager();
		long imageBase = optionalHeader.getImageBase();
		boolean is64 = optionalHeader.is64bit();
		DataType pointerType = new PointerDataType(null, -1, program.getDataTypeManager());

		log.appendMsg("CADRE PE Loader: processing " + descriptors.length
			+ " import descriptor(s) at image base 0x" + Long.toHexString(imageBase));

		int createdRefs = 0;
		int createdData = 0;
		int skipped = 0;

		for (ImportDescriptor descriptor : descriptors) {
			if (monitor.isCancelled()) {
				break;
			}

			String dll = descriptor.getDLL();
			if (dll == null || dll.isEmpty()) {
				continue;
			}

			ThunkData[] thunks = descriptor.getImportNameTableThunkData();
			if (thunks == null || thunks.length == 0) {
				continue;
			}

			int iatRva = descriptor.getFirstThunk();
			if (iatRva == 0) {
				continue;
			}

			for (int i = 0; i < thunks.length; i++) {
				if (monitor.isCancelled()) {
					break;
				}

				ThunkData thunk = thunks[i];
				if (thunk.getAddressOfData() == 0) {
					continue; // end of table
				}

				String name;
				long ordinal = -1;
				if (thunk.isOrdinal()) {
					ordinal = thunk.getOrdinal();
					name = "Ordinal_" + ordinal;
				}
				else {
					ImportByName ibn = thunk.getImportByName();
					name = ibn != null ? ibn.getName() : null;
					if (name == null || name.isEmpty()) {
						skipped++;
						continue;
					}
				}

				long addr = Integer.toUnsignedLong(iatRva + i * thunk.getStructSize()) + imageBase;
				if (!is64) {
					addr &= 0xffffffffL;
				}

				Address address;
				try {
					address = space.getAddress(addr);
				}
				catch (Exception e) {
					log.appendMsg("CADRE PE Loader: bad import address 0x"
						+ Long.toHexString(addr) + " for " + dll + "!" + name);
					continue;
				}

				if (!program.getMemory().contains(address)) {
					log.appendMsg("CADRE PE Loader: IAT slot not in memory: " + address
						+ " for " + dll + "!" + name);
					continue;
				}

				// Create pointer data at the IAT slot if it is missing or not a pointer.
				Data data = listing.getDefinedDataAt(address);
				if (data == null || !data.isPointer()) {
					try {
						data = DataUtilities.createData(program, address, pointerType, -1,
							DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
						createdData++;
					}
					catch (Exception e) {
						log.appendMsg("CADRE PE Loader: could not create pointer data at "
							+ address + " for " + dll + "!" + name + ": " + e.getMessage());
					}
				}

				// Skip if an external reference already exists at this address.
				boolean hasExternal = false;
				for (Reference ref : refMgr.getReferencesTo(address)) {
					if (ref.isExternalReference()) {
						hasExternal = true;
						break;
					}
				}
				if (hasExternal) {
					continue;
				}

				try {
					// Remove the memory reference created by the pointer data so the slot
					// is clearly an import thunk, not a pointer to an in-image address.
					Address extAddr = null;
					if (data != null && data.isPointer()) {
						Object value = data.getValue();
						if (value instanceof Address) {
							extAddr = (Address) value;
							try {
								data.removeOperandReference(0, extAddr);
							}
							catch (Exception e) {
								// ignore
							}
						}
					}

					refMgr.addExternalReference(address, dll.toUpperCase(), name, extAddr,
						SourceType.IMPORTED, 0, RefType.DATA);
					createdRefs++;
				}
				catch (InvalidInputException e) {
					log.appendMsg("CADRE PE Loader: invalid input for " + dll + "!"
						+ name + " at " + address + ": " + e.getMessage());
				}
				catch (Exception e) {
					log.appendMsg("CADRE PE Loader: failed to add external ref for " + dll
						+ "!" + name + " at " + address + ": " + e.getMessage());
				}
			}
		}

		log.appendMsg("CADRE PE Loader: created " + createdData + " pointer data items, "
			+ createdRefs + " external references, skipped " + skipped);
	}
}
