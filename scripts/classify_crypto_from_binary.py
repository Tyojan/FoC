#!/usr/bin/env python3
"""Classify crypto-related functions in a binary with FoC-Sim.

The classifier uses FoC-Sim as the primary signal: functions are embedded with
the FoC-Sim GNN/semantic encoder and compared against the known FoC-Sim
cryptographic reference database. FoC-BinLLM can optionally generate a readable
name/comment as a secondary explanation signal.

Example:
  python3 scripts/classify_crypto_from_binary.py ./sample.bin --output-json result.json

For the local environment in this repository, prefer:
  .venv/bin/python scripts/classify_crypto_from_binary.py ./sample.bin --output-json result.json
"""

from __future__ import annotations

import argparse
import csv
import importlib.util
import json
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


ROOT_DIR = Path(__file__).resolve().parents[1]
FOC_SIM_DIR = ROOT_DIR / "FoC-Sim"
FOC_SIM_SRC = FOC_SIM_DIR / "src"
UTILS_DIR = FOC_SIM_SRC / "utils"
SCRIPT_DIR = ROOT_DIR / "scripts"

for path in (FOC_SIM_SRC, UTILS_DIR, SCRIPT_DIR):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))


GHIDRA_SCRIPT_NAME = "FocSimExtract.java"
GHIDRA_SCRIPT = r'''
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class FocSimExtract extends GhidraScript {
    private static class Options {
        String output;
        int maxFunctions = -1;
        boolean includeThunks = false;
    }

    private static class BlockRecord {
        int id;
        String address;
        CodeBlock block;
        List<String> mnemonics = new ArrayList<String>();
    }

    @Override
    public void run() throws Exception {
        Options options = parseOptions(getScriptArgs());
        File outputJson = new File(options.output).getAbsoluteFile();

        String[] archBit = detectArchAndBit();
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
        Listing listing = currentProgram.getListing();

        List<String> records = new ArrayList<String>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (isExternalFunction(function)) {
                continue;
            }
            if (!options.includeThunks && isThunkFunction(function)) {
                continue;
            }
            records.add(buildFunctionRecord(
                records.size(),
                function,
                archBit[0],
                archBit[1],
                decompiler,
                blockModel,
                listing
            ));
            if (options.maxFunctions > 0 && records.size() >= options.maxFunctions) {
                break;
            }
        }

        decompiler.dispose();
        writeJsonArray(outputJson, records);
        println("[+] exported " + records.size() + " functions to " + outputJson);
    }

    private Options parseOptions(String[] args) {
        if (args.length < 1) {
            throw new IllegalArgumentException("usage: FocSimExtract <output-json> [--max-functions N] [--include-thunks]");
        }
        Options options = new Options();
        options.output = args[0];
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            if ("--max-functions".equals(arg)) {
                if (i + 1 >= args.length) {
                    throw new IllegalArgumentException("--max-functions requires a value");
                }
                options.maxFunctions = Integer.parseInt(args[++i]);
            } else if ("--include-thunks".equals(arg)) {
                options.includeThunks = true;
            }
        }
        return options;
    }

    private String[] detectArchAndBit() {
        String arch = "unknown";
        String bit = "unknown";
        try {
            String processor = currentProgram.getLanguage().getProcessor().toString();
            String lowered = processor.toLowerCase();
            if (lowered.indexOf("x86") >= 0 || lowered.indexOf("80386") >= 0) {
                arch = "x86";
            } else if (lowered.indexOf("aarch") >= 0 || lowered.indexOf("arm") >= 0) {
                arch = "arm";
            } else if (lowered.indexOf("mips") >= 0) {
                arch = "mips";
            } else if (processor.length() > 0) {
                arch = processor;
            }
        } catch (Exception ignored) {
        }
        try {
            bit = Integer.toString(currentProgram.getDefaultPointerSize() * 8);
        } catch (Exception ignored) {
        }
        return new String[] { arch, bit };
    }

    private boolean isExternalFunction(Function function) {
        try {
            return function.isExternal();
        } catch (Exception ignored) {
            return false;
        }
    }

    private boolean isThunkFunction(Function function) {
        try {
            return function.isThunk();
        } catch (Exception ignored) {
            return false;
        }
    }

    private String buildFunctionRecord(
        int fid,
        Function function,
        String arch,
        String bit,
        DecompInterface decompiler,
        BasicBlockModel blockModel,
        Listing listing
    ) throws Exception {
        List<BlockRecord> blocks = collectBlocks(function, blockModel, listing);
        List<int[]> edges = collectEdges(blocks);
        Set<String> callees = collectUniqueCallees(function);
        int calleeCount = countCallInstructions(function, listing);

        StringBuilder builder = new StringBuilder();
        builder.append("{");
        appendNumber(builder, "fid", fid, true);
        appendString(builder, "address", function.getEntryPoint().toString(), true);
        appendString(builder, "name", function.getName(), true);
        appendString(builder, "arch", arch, true);
        appendString(builder, "bit", bit, true);
        appendString(builder, "pcode", renderPseudocode(decompiler, function), true);
        appendNumber(builder, "callee_count", calleeCount, true);
        appendNumber(builder, "unique_callee_count", callees.size(), true);
        appendStringArray(builder, "callees", new ArrayList<String>(callees), true);
        appendBlocks(builder, "blocks", blocks, true);
        appendEdges(builder, "edges", edges, false);
        builder.append("}");
        return builder.toString();
    }

    private List<BlockRecord> collectBlocks(Function function, BasicBlockModel blockModel, Listing listing) {
        List<BlockRecord> records = new ArrayList<BlockRecord>();
        try {
            CodeBlockIterator iterator = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
            while (iterator.hasNext() && !monitor.isCancelled()) {
                CodeBlock block = iterator.next();
                BlockRecord record = new BlockRecord();
                record.id = records.size();
                record.block = block;
                record.address = block.getFirstStartAddress().toString();
                record.mnemonics = collectMnemonics(block, listing);
                records.add(record);
            }
        } catch (Exception ignored) {
        }
        return records;
    }

    private List<String> collectMnemonics(CodeBlock block, Listing listing) {
        List<String> mnemonics = new ArrayList<String>();
        try {
            InstructionIterator instructions = listing.getInstructions(block, true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = instructions.next();
                String mnemonic = instruction.getMnemonicString();
                if (mnemonic != null && mnemonic.length() > 0) {
                    mnemonics.add(mnemonic.toLowerCase());
                }
            }
        } catch (Exception ignored) {
        }
        return mnemonics;
    }

    private List<int[]> collectEdges(List<BlockRecord> blocks) {
        List<int[]> edges = new ArrayList<int[]>();
        HashSet<String> seen = new HashSet<String>();
        for (BlockRecord record : blocks) {
            try {
                CodeBlockReferenceIterator destinations = record.block.getDestinations(monitor);
                while (destinations.hasNext() && !monitor.isCancelled()) {
                    CodeBlockReference reference = destinations.next();
                    int dst = findBlockId(blocks, reference.getDestinationAddress());
                    if (dst < 0) {
                        continue;
                    }
                    String key = record.id + ":" + dst;
                    if (seen.contains(key)) {
                        continue;
                    }
                    seen.add(key);
                    edges.add(new int[] { record.id, dst });
                }
            } catch (Exception ignored) {
            }
        }
        return edges;
    }

    private int findBlockId(List<BlockRecord> blocks, Address address) {
        for (BlockRecord record : blocks) {
            try {
                if (record.block.contains(address)) {
                    return record.id;
                }
            } catch (Exception ignored) {
            }
            try {
                if (record.block.getFirstStartAddress().equals(address)) {
                    return record.id;
                }
            } catch (Exception ignored) {
            }
        }
        return -1;
    }

    private Set<String> collectUniqueCallees(Function function) {
        Set<String> callees = new HashSet<String>();
        try {
            Set<Function> calledFunctions = function.getCalledFunctions(monitor);
            for (Function callee : calledFunctions) {
                if (callee != null && callee.getName() != null) {
                    callees.add(callee.getName());
                }
            }
        } catch (Exception ignored) {
        }
        return callees;
    }

    private int countCallInstructions(Function function, Listing listing) {
        int count = 0;
        try {
            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
            while (instructions.hasNext() && !monitor.isCancelled()) {
                Instruction instruction = instructions.next();
                try {
                    if (instruction.getFlowType().isCall()) {
                        count++;
                    }
                } catch (Exception ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return count;
    }

    private String renderPseudocode(DecompInterface decompiler, Function function) {
        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results == null || !results.decompileCompleted() || results.getDecompiledFunction() == null) {
                return "";
            }
            String c = results.getDecompiledFunction().getC();
            return c == null ? "" : trimRight(c);
        } catch (Exception ignored) {
            return "";
        }
    }

    private void appendNumber(StringBuilder builder, String key, int value, boolean comma) {
        builder.append("\"").append(key).append("\":").append(value);
        builder.append(comma ? "," : "");
    }

    private void appendString(StringBuilder builder, String key, String value, boolean comma) {
        builder.append("\"").append(key).append("\":\"").append(jsonEscape(value)).append("\"");
        builder.append(comma ? "," : "");
    }

    private void appendStringArray(StringBuilder builder, String key, List<String> values, boolean comma) {
        builder.append("\"").append(key).append("\":[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                builder.append(",");
            }
            builder.append("\"").append(jsonEscape(values.get(i))).append("\"");
        }
        builder.append("]");
        builder.append(comma ? "," : "");
    }

    private void appendBlocks(StringBuilder builder, String key, List<BlockRecord> blocks, boolean comma) {
        builder.append("\"").append(key).append("\":[");
        for (int i = 0; i < blocks.size(); i++) {
            BlockRecord block = blocks.get(i);
            if (i > 0) {
                builder.append(",");
            }
            builder.append("{");
            appendNumber(builder, "id", block.id, true);
            appendString(builder, "address", block.address, true);
            appendStringArray(builder, "mnemonics", block.mnemonics, false);
            builder.append("}");
        }
        builder.append("]");
        builder.append(comma ? "," : "");
    }

    private void appendEdges(StringBuilder builder, String key, List<int[]> edges, boolean comma) {
        builder.append("\"").append(key).append("\":[");
        for (int i = 0; i < edges.size(); i++) {
            if (i > 0) {
                builder.append(",");
            }
            builder.append("[").append(edges.get(i)[0]).append(",").append(edges.get(i)[1]).append("]");
        }
        builder.append("]");
        builder.append(comma ? "," : "");
    }

    private void writeJsonArray(File outputJson, List<String> records) throws Exception {
        File parent = outputJson.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(outputJson), "UTF-8"));
        try {
            writer.write("[\n");
            for (int i = 0; i < records.size(); i++) {
                writer.write(records.get(i));
                if (i + 1 < records.size()) {
                    writer.write(",");
                }
                writer.write("\n");
            }
            writer.write("]\n");
        } finally {
            writer.close();
        }
    }

    private String trimRight(String value) {
        int end = value.length();
        while (end > 0 && Character.isWhitespace(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(0, end);
    }

    private String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            switch (ch) {
                case '"':
                    builder.append("\\\"");
                    break;
                case '\\':
                    builder.append("\\\\");
                    break;
                case '\b':
                    builder.append("\\b");
                    break;
                case '\f':
                    builder.append("\\f");
                    break;
                case '\n':
                    builder.append("\\n");
                    break;
                case '\r':
                    builder.append("\\r");
                    break;
                case '\t':
                    builder.append("\\t");
                    break;
                default:
                    if (ch < 0x20) {
                        builder.append(String.format("\\u%04x", (int) ch));
                    } else {
                        builder.append(ch);
                    }
                    break;
            }
        }
        return builder.toString();
    }
}
'''


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Classify crypto-related functions in a binary using FoC-Sim"
    )
    parser.add_argument("binary", nargs="?", help="Path to the input binary")
    parser.add_argument("--output-json", default="binary_crypto_results.json", help="Path to write result JSON")
    parser.add_argument(
        "--sim-checkpoint",
        default=str(FOC_SIM_DIR / "models" / "chkp_gnn-model" / "pytorch_model.bin"),
        help="FoC-Sim checkpoint path",
    )
    parser.add_argument(
        "--semantic-model",
        default=str(ROOT_DIR / "FoC-BinLLM-220m-ft"),
        help="FoC-BinLLM model directory used by the FoC-Sim semantic encoder and optional explanations",
    )
    parser.add_argument(
        "--reference-csv",
        default=str(FOC_SIM_DIR / "cryptobench" / "GCN" / "test.csv"),
        help="Known-function reference CSV",
    )
    parser.add_argument(
        "--reference-features",
        default=str(FOC_SIM_DIR / "cryptobench" / "GCN" / "test_all_feature.json"),
        help="Known-function FoC-Sim feature JSON",
    )
    parser.add_argument(
        "--reference-index",
        default=str(FOC_SIM_DIR / "cryptobench" / "GCN" / "test.focsim_index.pkl"),
        help="Cached normalized reference embedding index",
    )
    parser.add_argument(
        "--opcodes-dict",
        default=str(FOC_SIM_DIR / "cryptobench" / "GCN" / "opcodes_dict.json"),
        help="FoC-Sim opcode dictionary",
    )
    parser.add_argument("--ghidra-headless", default=None, help="Path to Ghidra analyzeHeadless")
    parser.add_argument("--device", default=None, help="Torch device, e.g. cuda, cuda:0, cpu")
    parser.add_argument("--top-k", type=int, default=10, help="Number of nearest reference matches to output")
    parser.add_argument("--sim-threshold", type=float, default=0.80, help="FoC-Sim positive threshold")
    parser.add_argument("--include-modes", action="store_true", help="Treat block/AE mode keywords as reference positives")
    parser.add_argument("--skip-binllm", action="store_true", help="Skip FoC-BinLLM explanation generation")
    parser.add_argument("--max-functions", type=int, default=None, help="Maximum functions to extract from the binary")
    parser.add_argument("--include-thunks", action="store_true", help="Include thunk functions from Ghidra")
    parser.add_argument("--batch-size", type=int, default=32, help="FoC-Sim embedding batch size")
    parser.add_argument("--binllm-batch-size", type=int, default=8, help="FoC-BinLLM generation batch size")
    parser.add_argument("--max-src-len", type=int, default=1024, help="FoC-BinLLM maximum input length")
    parser.add_argument("--max-tgt-len", type=int, default=256, help="FoC-BinLLM maximum generated length")
    parser.add_argument("--num-beams", type=int, default=1, help="FoC-BinLLM beam count")
    parser.add_argument("--no-repeat-ngram-size", type=int, default=0, help="FoC-BinLLM no-repeat ngram size")
    parser.add_argument("--rebuild-index", action="store_true", help="Rebuild the reference embedding index")
    parser.add_argument("--reference-limit", type=int, default=None, help="Limit reference rows when building a new index")
    parser.add_argument("--keep-ghidra-project", action="store_true", help="Keep the temporary Ghidra project directory")
    parser.add_argument("--keep-extracted-json", default=None, help="Copy raw Ghidra extraction JSON to this path")
    parser.add_argument("--self-test", action="store_true", help="Run local feature-conversion checks and exit")
    return parser.parse_args()


def require_python_packages(skip_binllm: bool) -> None:
    required = ["numpy", "torch", "transformers", "scipy", "tqdm"]
    missing = [pkg for pkg in required if importlib.util.find_spec(pkg) is None]
    if missing:
        raise SystemExit(
            "Missing Python packages: {0}. Run this with .venv/bin/python or install requirements.txt.".format(
                ", ".join(missing)
            )
        )


def resolve_existing_file(path: str, description: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise SystemExit("{0} not found: {1}".format(description, resolved))
    return resolved


def resolve_existing_dir(path: str, description: str) -> Path:
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        raise SystemExit("{0} not found: {1}".format(description, resolved))
    return resolved


def chunked(items: Sequence[Any], batch_size: int) -> Iterable[Sequence[Any]]:
    for start in range(0, len(items), batch_size):
        yield items[start:start + batch_size]


def executable_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    candidate = Path(os.path.expandvars(os.path.expanduser(path)))
    if candidate.is_file() and os.access(str(candidate), os.X_OK):
        return str(candidate.resolve())
    return None


def find_ghidra_headless(cli_path: Optional[str]) -> Optional[str]:
    names = ["analyzeHeadless.bat", "analyzeHeadless"] if os.name == "nt" else ["analyzeHeadless"]
    relative_names = names + [str(Path("support") / name) for name in names]

    for value in (
        cli_path,
        os.environ.get("GHIDRA_HEADLESS"),
        os.environ.get("GHIDRA_HOME"),
        os.environ.get("GHIDRA_INSTALL_DIR"),
    ):
        if not value:
            continue
        root = Path(os.path.expandvars(os.path.expanduser(value)))
        if root.is_file():
            found = executable_path(str(root))
            if found:
                return found
        if root.is_dir():
            for relname in relative_names:
                found = executable_path(str(root / relname))
                if found:
                    return found

    found = shutil.which("analyzeHeadless")
    if found:
        return found

    for root in (Path("/opt"), Path.home() / "tools", Path.home() / "apps", Path.home() / "ango" / "tools"):
        if not root.is_dir():
            continue
        for entry in sorted(root.iterdir()):
            if "ghidra" not in entry.name.lower():
                continue
            for relname in relative_names:
                found = executable_path(str(entry / relname))
                if found:
                    return found
    return None


def quote_for_log(value: str) -> str:
    if any(ch.isspace() or ch in value for ch in ['"', "\\"]):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def run_ghidra_extractor(args: argparse.Namespace, binary_path: Path) -> List[Dict[str, Any]]:
    headless = find_ghidra_headless(args.ghidra_headless)
    if not headless:
        raise SystemExit(
            "Ghidra analyzeHeadless was not found. Set GHIDRA_HOME, GHIDRA_HEADLESS, or pass --ghidra-headless."
        )

    created_project_dir: Optional[str] = None
    raw_fd, raw_path = tempfile.mkstemp(prefix="focsim_extract_", suffix=".json")
    os.close(raw_fd)
    script_dir = tempfile.mkdtemp(prefix="focsim_ghidra_script_")
    if args.keep_ghidra_project:
        project_dir = tempfile.mkdtemp(prefix="focsim_ghidra_project_")
    else:
        project_dir = tempfile.mkdtemp(prefix="focsim_ghidra_project_")
        created_project_dir = project_dir

    try:
        script_path = Path(script_dir) / GHIDRA_SCRIPT_NAME
        script_path.write_text(GHIDRA_SCRIPT.lstrip(), encoding="utf-8")

        script_args = [raw_path]
        if args.max_functions is not None:
            script_args.extend(["--max-functions", str(args.max_functions)])
        if args.include_thunks:
            script_args.append("--include-thunks")

        cmd = [
            headless,
            project_dir,
            "focsim_extract",
            "-import",
            str(binary_path),
            "-scriptPath",
            script_dir,
            "-postScript",
            GHIDRA_SCRIPT_NAME,
        ] + script_args
        if not args.keep_ghidra_project:
            cmd.append("-deleteProject")

        print("[+] running: {0}".format(" ".join(quote_for_log(part) for part in cmd)))
        subprocess.run(cmd, check=True)

        raw_records = json.loads(Path(raw_path).read_text(encoding="utf-8"))
        if args.keep_extracted_json:
            keep_path = Path(args.keep_extracted_json).expanduser().resolve()
            keep_path.parent.mkdir(parents=True, exist_ok=True)
            keep_path.write_text(json.dumps(raw_records, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return raw_records
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)
        if created_project_dir:
            shutil.rmtree(created_project_dir, ignore_errors=True)
        try:
            os.unlink(raw_path)
        except OSError:
            pass


def normalize_arch(value: str) -> str:
    lowered = (value or "").lower()
    if "x86" in lowered or "80386" in lowered or "metapc" in lowered:
        return "x86"
    if "aarch" in lowered or "arm" in lowered:
        return "arm"
    if "mips" in lowered:
        return "mips"
    return lowered or "unknown"


def load_feature_resources(opcodes_path: Path) -> Dict[str, Any]:
    from architecture import ARCH_MNEM  # type: ignore
    from evaluate_crypto_label import AE_mode, block_crypto_mode, crypto_class, get_label  # type: ignore

    with opcodes_path.open("r", encoding="utf-8") as handle:
        opcodes = json.load(handle)

    all_categories: Dict[str, set] = {}
    for arch_categories in ARCH_MNEM.values():
        for category, values in arch_categories.items():
            all_categories.setdefault(category, set()).update(values)

    return {
        "opcodes": {str(key).lower(): int(value) for key, value in opcodes.items()},
        "arch_mnem": ARCH_MNEM,
        "all_categories": all_categories,
        "crypto_names": list(crypto_class.keys()),
        "block_modes": list(block_crypto_mode),
        "ae_modes": list(AE_mode),
        "get_label": get_label,
    }


def category_values(resources: Dict[str, Any], arch: str, category: str) -> set:
    arch_key = normalize_arch(arch)
    arch_categories = resources["arch_mnem"].get(arch_key)
    if arch_categories is not None and category in arch_categories:
        return arch_categories[category]
    return resources["all_categories"].get(category, set())


def sparse_string_from_entries(entries: Dict[Tuple[int, int], int], n_rows: int, n_cols: int) -> str:
    ordered = sorted((row, col, value) for (row, col), value in entries.items() if value != 0)
    row_str = ";".join(str(row) for row, _col, _value in ordered)
    col_str = ";".join(str(col) for _row, col, _value in ordered)
    data_str = ";".join(str(value) for _row, _col, value in ordered)
    return "{0}::{1}::{2}::{3}::{4}".format(row_str, col_str, data_str, n_rows, n_cols)


def sparse_string_to_numpy(mat_str: str) -> Any:
    import numpy as np

    row_str, col_str, data_str, n_row, n_col = mat_str.split("::")
    n_row_int = int(n_row)
    n_col_int = int(n_col)
    if row_str == "" or col_str == "" or data_str == "":
        return np.identity(n_col_int, dtype=np.float32)
    matrix = np.zeros((n_row_int, n_col_int), dtype=np.float32)
    rows = [int(value) for value in row_str.split(";")]
    cols = [int(value) for value in col_str.split(";")]
    data = [float(value) for value in data_str.split(";")]
    for row, col, value in zip(rows, cols, data):
        matrix[row, col] = value
    return matrix


def graph_sparse_string(n_blocks: int, edges: Sequence[Sequence[int]]) -> str:
    n_blocks = max(1, n_blocks)
    entries: Dict[Tuple[int, int], int] = {}
    for edge in edges:
        if len(edge) != 2:
            continue
        src, dst = int(edge[0]), int(edge[1])
        if 0 <= src < n_blocks and 0 <= dst < n_blocks:
            entries[(src, dst)] = 1
    return sparse_string_from_entries(entries, n_blocks, n_blocks)


def opcode_sparse_string(blocks: Sequence[Dict[str, Any]], arch: str, resources: Dict[str, Any]) -> str:
    n_blocks = max(1, len(blocks))
    opcodes: Dict[str, int] = resources["opcodes"]
    arithmetic = category_values(resources, arch, "arithmetic")
    logic = category_values(resources, arch, "logic")
    unconditional = category_values(resources, arch, "unconditional")
    conditional = category_values(resources, arch, "conditional")
    call = category_values(resources, arch, "call")
    control_flow = set().union(unconditional, conditional, call)

    entries: Dict[Tuple[int, int], int] = {}
    for row in range(n_blocks):
        block = blocks[row] if row < len(blocks) else {}
        mnemonics = [str(item).lower() for item in block.get("mnemonics", []) if str(item).strip()]
        total = 0
        arithmetic_count = 0
        logic_count = 0
        control_count = 0
        for mnemonic in mnemonics:
            total += 1
            if mnemonic in opcodes:
                key = (row, opcodes[mnemonic])
                entries[key] = entries.get(key, 0) + 1
            if mnemonic in arithmetic:
                arithmetic_count += 1
            if mnemonic in logic:
                logic_count += 1
            if mnemonic in control_flow:
                control_count += 1
        for col, value in ((196, total), (197, arithmetic_count), (198, logic_count), (199, control_count)):
            if value:
                entries[(row, col)] = entries.get((row, col), 0) + value

    if not entries:
        entries[(0, 196)] = 1
    return sparse_string_from_entries(entries, n_blocks, 200)


def anonymize_pcode(pcode: str, function_name: str) -> str:
    if not pcode:
        return ""
    if function_name:
        return pcode.replace(function_name, "<FUNCTION>")
    return pcode


def keywords_to_feature_vector(keywords: Dict[str, set], resources: Dict[str, Any]) -> List[float]:
    values: List[float] = []
    for name in resources["crypto_names"]:
        values.append(1.0 if name in keywords["crypto_class"] else 0.0)
    for mode in resources["block_modes"]:
        values.append(1.0 if mode in keywords["block_mode"] else 0.0)
    for mode in resources["ae_modes"]:
        values.append(1.0 if mode in keywords["ae_mode"] else 0.0)
    return values


def decode_feature_keywords(feature: Sequence[float], resources: Dict[str, Any]) -> Dict[str, List[str]]:
    crypto_count = len(resources["crypto_names"])
    block_count = len(resources["block_modes"])
    ae_count = len(resources["ae_modes"])
    crypto_values = feature[:crypto_count]
    block_values = feature[crypto_count:crypto_count + block_count]
    ae_values = feature[crypto_count + block_count:crypto_count + block_count + ae_count]
    return {
        "crypto_class": [name for name, value in zip(resources["crypto_names"], crypto_values) if value],
        "block_mode": [name for name, value in zip(resources["block_modes"], block_values) if value],
        "ae_mode": [name for name, value in zip(resources["ae_modes"], ae_values) if value],
    }


def raw_function_to_feature_item(raw: Dict[str, Any], resources: Dict[str, Any]) -> Dict[str, Any]:
    name = str(raw.get("name") or "")
    pcode = anonymize_pcode(str(raw.get("pcode") or ""), name)
    blocks = raw.get("blocks") or []
    edges = raw.get("edges") or []
    arch = normalize_arch(str(raw.get("arch") or "unknown"))
    block_count = max(1, len(blocks))
    edge_count = len(edges)
    callee_count = int(raw.get("callee_count") or 0)
    unique_callee_count = int(raw.get("unique_callee_count") or 0)

    get_label = resources["get_label"]
    keywords = get_label(name, pcode, "")
    feature = keywords_to_feature_vector(keywords, resources)
    feature.extend([
        float(unique_callee_count),
        float(callee_count),
        float(edge_count),
        float(block_count),
    ])

    return {
        "fid": int(raw.get("fid") or 0),
        "address": str(raw.get("address") or ""),
        "name": name,
        "arch": arch,
        "bit": str(raw.get("bit") or ""),
        "pcode": pcode,
        "graph": graph_sparse_string(block_count, edges),
        "opc": opcode_sparse_string(blocks, arch, resources),
        "feature": feature,
        "source_matched_keywords": {
            "crypto_class": sorted(keywords["crypto_class"]),
            "block_mode": sorted(keywords["block_mode"]),
            "ae_mode": sorted(keywords["ae_mode"]),
        },
    }


def collate_feature_items(items: Sequence[Dict[str, Any]], device: Any) -> Dict[str, Any]:
    import numpy as np
    import torch

    node_features = []
    edge_features = []
    from_idx = []
    to_idx = []
    graph_idx = []
    pcode = []
    fea_embed = []
    n_total_nodes = 0

    for idx, item in enumerate(items):
        graph = sparse_string_to_numpy(item["graph"])
        opc = sparse_string_to_numpy(item["opc"])
        edge_rows, edge_cols = np.nonzero(graph)
        if len(edge_rows) == 0:
            edge_rows = np.arange(graph.shape[0], dtype=np.int64)
            edge_cols = np.arange(graph.shape[0], dtype=np.int64)
        edges = np.stack([edge_rows, edge_cols], axis=1).astype(np.int32)

        node_features.append(np.float32(opc))
        edge_features.append(np.zeros((len(edges), 1), dtype=np.float32))
        from_idx.append(edges[:, 0] + n_total_nodes)
        to_idx.append(edges[:, 1] + n_total_nodes)
        graph_idx.append(np.ones(opc.shape[0], dtype=np.int32) * idx)
        pcode.append(item["pcode"])
        fea_embed.append(np.float32(item["feature"]))
        n_total_nodes += opc.shape[0]

    return {
        "node_features": torch.from_numpy(np.concatenate(node_features, axis=0)).to(device),
        "edge_features": torch.from_numpy(np.concatenate(edge_features, axis=0)).to(device),
        "from_idx": torch.from_numpy(np.concatenate(from_idx, axis=0)).long().to(device),
        "to_idx": torch.from_numpy(np.concatenate(to_idx, axis=0)).long().to(device),
        "graph_idx": torch.from_numpy(np.concatenate(graph_idx, axis=0)).long().to(device),
        "n_graphs": len(items),
        "pcode": pcode,
        "fea_embed": torch.tensor(np.array(fea_embed), dtype=torch.float32).to(device),
    }


def load_focsim_model(checkpoint_path: Path, semantic_model_path: Path, device: Any) -> Any:
    import torch
    from GNN.graphembeddingnetwork import GraphEmbeddingNet, build_model, get_default_config  # type: ignore

    class GraphModelForACFGInference(GraphEmbeddingNet):
        def forward(
            self,
            node_features,
            edge_features,
            from_idx,
            to_idx,
            graph_idx,
            n_graphs,
            pcode,
            fea_embed,
            generate_emb: bool = False,
        ):
            node_features, edge_features = self._graphencoder(node_features, edge_features)
            node_states = node_features
            for layer in self._prop_layers:
                node_states = self._apply_layer(
                    layer,
                    node_states,
                    from_idx,
                    to_idx,
                    graph_idx,
                    n_graphs,
                    edge_features,
                )
            graph_embs = self._aggregator(node_states, graph_idx, n_graphs)
            with torch.no_grad():
                pcode_embed = self._codet5encoder(pcode)
            graph_embs = torch.cat((graph_embs, pcode_embed), dim=1)
            graph_embs = torch.cat((graph_embs, fea_embed), dim=1)
            fusion_embs = self._fusionembedder(graph_embs)
            if generate_emb:
                return fusion_embs
            return fusion_embs

    config = get_default_config()
    config["codet5encoder"]["checkpoint_path"] = str(semantic_model_path)
    model = build_model(config, GraphModelForACFGInference, node_feature_dim=200, edge_feature_dim=1)
    state = torch.load(str(checkpoint_path), map_location=device)
    model.load_state_dict(state)
    model.to(device)
    model.eval()
    return model


def embed_feature_items(model: Any, items: Sequence[Dict[str, Any]], device: Any, batch_size: int) -> Any:
    import numpy as np
    import torch
    from tqdm import tqdm

    if not items:
        return np.zeros((0, 256), dtype=np.float32)

    batches = list(chunked(items, batch_size))
    embeddings = []
    with torch.no_grad():
        for batch_items in tqdm(batches, desc="FoC-Sim embedding"):
            batch = collate_feature_items(batch_items, device)
            embs = model(**batch, generate_emb=True)
            embs = torch.nn.functional.normalize(embs.float(), p=2, dim=1)
            embeddings.append(embs.detach().cpu().numpy().astype("float32"))
    return np.concatenate(embeddings, axis=0)


def read_reference_rows(reference_csv: Path, limit: Optional[int]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    with reference_csv.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(dict(row))
            if limit is not None and len(rows) >= limit:
                break
    return rows


def build_reference_index(
    args: argparse.Namespace,
    model: Any,
    device: Any,
    resources: Dict[str, Any],
    reference_csv: Path,
    reference_features: Path,
    reference_index: Path,
) -> Dict[str, Any]:
    import numpy as np

    print("[+] building FoC-Sim reference index from {0}".format(reference_csv))
    rows = read_reference_rows(reference_csv, args.reference_limit)
    with reference_features.open("r", encoding="utf-8") as handle:
        features = json.load(handle)

    items: List[Dict[str, Any]] = []
    metadata: List[Dict[str, Any]] = []
    crypto_class_positive: List[bool] = []
    any_keyword_positive: List[bool] = []

    for row in rows:
        fid = str(row["fid"])
        feature_item = features.get(fid)
        if feature_item is None:
            continue
        feature = feature_item["feature"]
        items.append(
            {
                "fid": int(fid),
                "graph": feature_item["graph"],
                "opc": feature_item["opc"],
                "pcode": feature_item["pcode"],
                "feature": feature,
            }
        )
        metadata.append(
            {
                "fid": int(fid),
                "func_name": row.get("func_name", ""),
                "project": row.get("project", ""),
                "arch": row.get("arch", ""),
                "bit": row.get("bit", ""),
                "compiler": row.get("compiler", ""),
                "opti": row.get("opti", ""),
                "md5": row.get("md5", ""),
                "blocks_num": row.get("blocks_num", ""),
                "matched_keywords": decode_feature_keywords(feature, resources),
            }
        )
        crypto_class_positive.append(any(feature[:len(resources["crypto_names"])]))
        any_keyword_positive.append(any(feature[:61]))

    embeddings = embed_feature_items(model, items, device, args.batch_size)
    index = {
        "version": 1,
        "reference_csv": str(reference_csv),
        "reference_features": str(reference_features),
        "sim_checkpoint": str(Path(args.sim_checkpoint).expanduser().resolve()),
        "semantic_model": str(Path(args.semantic_model).expanduser().resolve()),
        "metadata": metadata,
        "embeddings": embeddings.astype("float32"),
        "crypto_class_positive": np.array(crypto_class_positive, dtype=bool),
        "any_keyword_positive": np.array(any_keyword_positive, dtype=bool),
    }

    reference_index.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = reference_index.with_suffix(reference_index.suffix + ".tmp")
    with tmp_path.open("wb") as handle:
        pickle.dump(index, handle, protocol=pickle.HIGHEST_PROTOCOL)
    os.replace(str(tmp_path), str(reference_index))
    print("[+] saved FoC-Sim reference index to {0}".format(reference_index))
    return index


def load_or_build_reference_index(
    args: argparse.Namespace,
    model: Any,
    device: Any,
    resources: Dict[str, Any],
    reference_csv: Path,
    reference_features: Path,
    reference_index: Path,
) -> Dict[str, Any]:
    if reference_index.is_file() and not args.rebuild_index:
        print("[+] loading FoC-Sim reference index from {0}".format(reference_index))
        with reference_index.open("rb") as handle:
            return pickle.load(handle)
    return build_reference_index(args, model, device, resources, reference_csv, reference_features, reference_index)


def top_match_records(
    scores: Any,
    index: Dict[str, Any],
    positive_mask: Any,
    top_k: int,
) -> List[Dict[str, Any]]:
    import numpy as np

    if len(scores) == 0:
        return []
    k = max(0, min(top_k, len(scores)))
    if k == 0:
        return []
    top_indices = np.argpartition(-scores, k - 1)[:k]
    top_indices = top_indices[np.argsort(-scores[top_indices])]
    matches: List[Dict[str, Any]] = []
    for idx in top_indices:
        meta = index["metadata"][int(idx)]
        matches.append(
            {
                "fid": meta["fid"],
                "func_name": meta["func_name"],
                "project": meta["project"],
                "arch": meta["arch"],
                "bit": meta["bit"],
                "compiler": meta["compiler"],
                "opti": meta["opti"],
                "score": float(scores[int(idx)]),
                "crypto_reference": bool(positive_mask[int(idx)]),
                "matched_keywords": meta["matched_keywords"],
            }
        )
    return matches


def classify_embeddings(query_embeddings: Any, index: Dict[str, Any], args: argparse.Namespace) -> List[Dict[str, Any]]:
    import numpy as np

    ref_embeddings = index["embeddings"]
    positive_mask = index["any_keyword_positive"] if args.include_modes else index["crypto_class_positive"]
    positive_indices = np.flatnonzero(positive_mask)
    results: List[Dict[str, Any]] = []

    for query_embedding in query_embeddings:
        scores = ref_embeddings @ query_embedding
        top_matches = top_match_records(scores, index, positive_mask, args.top_k)
        if len(positive_indices) == 0:
            best_positive_score = None
            best_positive_match = None
            crypto_label = False
        else:
            positive_scores = scores[positive_indices]
            best_pos_offset = int(np.argmax(positive_scores))
            best_pos_idx = int(positive_indices[best_pos_offset])
            best_positive_score = float(scores[best_pos_idx])
            meta = index["metadata"][best_pos_idx]
            best_positive_match = {
                "fid": meta["fid"],
                "func_name": meta["func_name"],
                "project": meta["project"],
                "arch": meta["arch"],
                "bit": meta["bit"],
                "score": best_positive_score,
                "matched_keywords": meta["matched_keywords"],
            }
            crypto_label = best_positive_score >= args.sim_threshold

        if best_positive_score is None:
            decision_reason = "foc_sim_negative: no positive references are present in the reference index"
        elif crypto_label:
            decision_reason = (
                "foc_sim_positive: best positive reference score "
                "{0:.4f} >= threshold {1:.4f}".format(best_positive_score, args.sim_threshold)
            )
        else:
            decision_reason = (
                "foc_sim_negative: best positive reference score "
                "{0:.4f} < threshold {1:.4f}".format(best_positive_score, args.sim_threshold)
            )

        results.append(
            {
                "crypto_label": bool(crypto_label),
                "sim_score": best_positive_score,
                "best_positive_match": best_positive_match,
                "top_matches": top_matches,
                "decision_reason": decision_reason,
            }
        )
    return results


def run_binllm_predictions(
    items: Sequence[Dict[str, Any]],
    args: argparse.Namespace,
    device: Any,
) -> List[Dict[str, Any]]:
    if args.skip_binllm:
        return [
            {
                "predicted_comment_and_name": "",
                "predicted_comment": "",
                "predicted_name": "",
                "binllm_crypto_label": False,
                "matched_keywords": item["source_matched_keywords"],
                "source_matched_keywords": item["source_matched_keywords"],
            }
            for item in items
        ]

    from classify_crypto_from_pcode import (  # type: ignore
        classify_prediction,
        generate_comment_and_name_batch,
        load_model,
        parse_comment_and_name,
    )
    from tqdm import tqdm

    tokenizer, model = load_model(str(Path(args.semantic_model).expanduser().resolve()), device)
    llm_args = SimpleNamespace(
        max_src_len=args.max_src_len,
        max_tgt_len=args.max_tgt_len,
        num_beams=args.num_beams,
        no_repeat_ngram_size=args.no_repeat_ngram_size,
    )
    results: List[Dict[str, Any]] = []
    batches = list(chunked(items, args.binllm_batch_size))
    for batch in tqdm(batches, desc="FoC-BinLLM generation"):
        generated_list = generate_comment_and_name_batch(
            tokenizer,
            model,
            [item["pcode"] for item in batch],
            device,
            llm_args,
        )
        for item, generated in zip(batch, generated_list):
            parsed = parse_comment_and_name(generated)
            classification = classify_prediction(parsed, include_modes=args.include_modes, source_name=item["name"])
            results.append(
                {
                    "predicted_comment_and_name": generated,
                    "predicted_comment": parsed["comment"],
                    "predicted_name": parsed["name"],
                    "binllm_crypto_label": classification["crypto_label"],
                    "matched_keywords": classification["matched_keywords"],
                    "source_matched_keywords": item["source_matched_keywords"],
                }
            )
    return results


def select_device(device_arg: Optional[str]) -> Any:
    import torch

    if device_arg:
        return torch.device(device_arg)
    return torch.device("cuda" if torch.cuda.is_available() else "cpu")


def run_self_test() -> None:
    require_python_packages(skip_binllm=True)
    opcodes_path = resolve_existing_file(str(FOC_SIM_DIR / "cryptobench" / "GCN" / "opcodes_dict.json"), "opcode dictionary")
    resources = load_feature_resources(opcodes_path)
    raw = {
        "fid": 0,
        "address": "00100000",
        "name": "aes_encrypt",
        "arch": "x86",
        "bit": "64",
        "pcode": "void aes_encrypt(unsigned char *out) { aes_encrypt(out); }",
        "callee_count": 1,
        "unique_callee_count": 1,
        "blocks": [
            {"id": 0, "address": "00100000", "mnemonics": ["push", "mov", "xor", "call"]},
            {"id": 1, "address": "00100010", "mnemonics": ["ret"]},
        ],
        "edges": [[0, 1]],
    }
    item = raw_function_to_feature_item(raw, resources)

    graph = sparse_string_to_numpy(item["graph"])
    opc = sparse_string_to_numpy(item["opc"])
    assert graph.shape == (2, 2), graph.shape
    assert opc.shape == (2, 200), opc.shape
    assert len(item["feature"]) == 65, len(item["feature"])
    assert item["feature"][resources["crypto_names"].index("aes")] == 1.0
    print("[+] self-test passed")


def main() -> None:
    args = parse_args()
    if args.self_test:
        run_self_test()
        return
    if not args.binary:
        raise SystemExit("binary is required unless --self-test is used")

    require_python_packages(skip_binllm=args.skip_binllm)
    binary_path = resolve_existing_file(args.binary, "input binary")
    checkpoint_path = resolve_existing_file(args.sim_checkpoint, "FoC-Sim checkpoint")
    semantic_model_path = resolve_existing_dir(args.semantic_model, "semantic model directory")
    reference_csv = resolve_existing_file(args.reference_csv, "reference CSV")
    reference_features = resolve_existing_file(args.reference_features, "reference feature JSON")
    opcodes_path = resolve_existing_file(args.opcodes_dict, "opcode dictionary")
    reference_index = Path(args.reference_index).expanduser().resolve()

    resources = load_feature_resources(opcodes_path)
    raw_records = run_ghidra_extractor(args, binary_path)
    feature_items = [raw_function_to_feature_item(raw, resources) for raw in raw_records]

    device = select_device(args.device)
    print("[+] using device: {0}".format(device))
    sim_model = load_focsim_model(checkpoint_path, semantic_model_path, device)
    index = load_or_build_reference_index(
        args,
        sim_model,
        device,
        resources,
        reference_csv,
        reference_features,
        reference_index,
    )
    query_embeddings = embed_feature_items(sim_model, feature_items, device, args.batch_size)
    sim_results = classify_embeddings(query_embeddings, index, args)

    del sim_model
    try:
        import torch

        if device.type == "cuda":
            torch.cuda.empty_cache()
    except Exception:
        pass

    llm_results = run_binllm_predictions(feature_items, args, device)

    functions: List[Dict[str, Any]] = []
    for raw, item, sim_result, llm_result in zip(raw_records, feature_items, sim_results, llm_results):
        functions.append(
            {
                "fid": item["fid"],
                "address": item["address"],
                "name": item["name"],
                "crypto_label": sim_result["crypto_label"],
                "sim_score": sim_result["sim_score"],
                "top_matches": sim_result["top_matches"],
                "matched_keywords": llm_result["matched_keywords"],
                "predicted_comment": llm_result["predicted_comment"],
                "predicted_name": llm_result["predicted_name"],
                "decision_reason": sim_result["decision_reason"],
                "best_positive_match": sim_result["best_positive_match"],
                "binllm_crypto_label": llm_result["binllm_crypto_label"],
                "source_matched_keywords": llm_result["source_matched_keywords"],
                "arch": item["arch"],
                "bit": item["bit"],
                "blocks": len(raw.get("blocks") or []),
                "edges": len(raw.get("edges") or []),
            }
        )

    output = {
        "binary": str(binary_path),
        "sim_threshold": args.sim_threshold,
        "include_modes": args.include_modes,
        "reference_index": str(reference_index),
        "function_count": len(functions),
        "crypto_function_count": sum(1 for item in functions if item["crypto_label"]),
        "functions": functions,
    }
    output_path = Path(args.output_json).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print("[+] results saved to: {0}".format(output_path))


if __name__ == "__main__":
    main()
