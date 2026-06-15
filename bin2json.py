"""Export decompiled functions from a binary into FoC-style JSON.

Default host usage:
  python3 bin2json.py <input-binary> <output-json>

The host mode prefers IDA headless when an IDA executable is detected. If IDA
cannot be found, it falls back to Ghidra headless (`analyzeHeadless`).

Direct IDA usage:
  idat64 -A -S"bin2json.py -- <input-binary> <output-json>" <input-binary>

Direct Ghidra usage:
  analyzeHeadless /tmp/bin2json_proj bin2json -import <input-binary> \
    -postScript bin2json.py <input-binary> <output-json> -deleteProject
"""

import argparse
import hashlib
import json
import os
import sys


PY2 = sys.version_info[0] == 2

ida_funcs = None
ida_hexrays = None
ida_ida = None
ida_lines = None
ida_name = None
idautils = None
idc = None

GHIDRA_JAVA_SCRIPT_NAME = "Bin2JsonExport.java"
GHIDRA_JAVA_SCRIPT = r'''
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class Bin2JsonExport extends GhidraScript {
    private static class Options {
        String binary;
        String output;
        String project;
        String version = "";
        String compiler = "unknown";
        String arch;
        String bit;
        String opti = "unknown";
        String smd5;
        boolean includeLibrary = false;
        boolean includeThunks = false;
    }

    @Override
    public void run() throws Exception {
        Options options = parseOptions(getScriptArgs());
        File inputBinary = new File(options.binary).getAbsoluteFile();
        File outputJson = new File(options.output).getAbsoluteFile();
        if (!inputBinary.isFile()) {
            throw new IllegalArgumentException("input binary not found: " + inputBinary);
        }

        if (options.project == null) {
            options.project = stripExtension(inputBinary.getName());
        }
        if (options.arch == null || options.bit == null) {
            String[] detected = detectArchAndBit();
            if (options.arch == null) {
                options.arch = detected[0];
            }
            if (options.bit == null) {
                options.bit = detected[1];
            }
        }

        String binaryMd5 = md5OfFile(inputBinary);
        if (options.smd5 == null) {
            options.smd5 = binaryMd5;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        List<String> records = new ArrayList<String>();
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (!options.includeLibrary && isLibraryFunction(function)) {
                continue;
            }
            if (!options.includeThunks && isThunkFunction(function)) {
                continue;
            }

            String name = functionName(function);
            String comment = functionComment(function);
            String pcode = renderPseudocode(decompiler, function);
            records.add(buildRecord(
                records.size(),
                options.project,
                options.version,
                options.compiler,
                options.arch,
                options.bit,
                options.opti,
                binaryMd5,
                options.smd5,
                pcode,
                comment,
                name
            ));
        }

        decompiler.dispose();
        writeJsonArray(outputJson, records);
        println("[+] exported " + records.size() + " functions to " + outputJson);
    }

    private Options parseOptions(String[] args) {
        Options options = new Options();
        List<String> positional = new ArrayList<String>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--project".equals(arg)) {
                options.project = requireValue(args, ++i, arg);
            } else if ("--version".equals(arg)) {
                options.version = requireValue(args, ++i, arg);
            } else if ("--compiler".equals(arg)) {
                options.compiler = requireValue(args, ++i, arg);
            } else if ("--arch".equals(arg)) {
                options.arch = requireValue(args, ++i, arg);
            } else if ("--bit".equals(arg)) {
                options.bit = requireValue(args, ++i, arg);
            } else if ("--opti".equals(arg)) {
                options.opti = requireValue(args, ++i, arg);
            } else if ("--smd5".equals(arg)) {
                options.smd5 = requireValue(args, ++i, arg);
            } else if ("--include-library".equals(arg)) {
                options.includeLibrary = true;
            } else if ("--include-thunks".equals(arg)) {
                options.includeThunks = true;
            } else {
                positional.add(arg);
            }
        }
        if (positional.size() < 2) {
            throw new IllegalArgumentException("usage: Bin2JsonExport <input-binary> <output-json> [options]");
        }
        options.binary = positional.get(0);
        options.output = positional.get(1);
        return options;
    }

    private String requireValue(String[] args, int index, String option) {
        if (index >= args.length) {
            throw new IllegalArgumentException(option + " requires a value");
        }
        return args[index];
    }

    private String[] detectArchAndBit() {
        String arch = "unknown";
        String bit = "unknown";
        try {
            String processor = currentProgram.getLanguage().getProcessor().toString();
            String lowered = processor.toLowerCase();
            if (lowered.indexOf("x86") >= 0 || lowered.indexOf("80386") >= 0) {
                arch = "x86";
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

    private boolean isLibraryFunction(Function function) {
        try {
            if (function.isExternal()) {
                return true;
            }
        } catch (Exception ignored) {
        }
        try {
            Symbol symbol = function.getSymbol();
            if (symbol != null && symbol.isExternal()) {
                return true;
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private boolean isThunkFunction(Function function) {
        try {
            return function.isThunk();
        } catch (Exception ignored) {
            return false;
        }
    }

    private String functionName(Function function) {
        try {
            String name = function.getName();
            if (name != null && name.length() > 0) {
                return name;
            }
        } catch (Exception ignored) {
        }
        try {
            return "sub_" + function.getEntryPoint().toString();
        } catch (Exception ignored) {
            return "sub_unknown";
        }
    }

    private String functionComment(Function function) {
        List<String> comments = new ArrayList<String>();
        try {
            String comment = function.getComment();
            if (comment != null && comment.trim().length() > 0) {
                comments.add(comment.trim());
            }
        } catch (Exception ignored) {
        }
        try {
            String comment = function.getRepeatableComment();
            if (comment != null && comment.trim().length() > 0) {
                comments.add(comment.trim());
            }
        } catch (Exception ignored) {
        }
        return joinUnique(comments, " ");
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

    private String buildRecord(
        int fid,
        String project,
        String version,
        String compiler,
        String arch,
        String bit,
        String opti,
        String md5,
        String smd5,
        String pcode,
        String comment,
        String name
    ) {
        String commentAndName = "<COMMENT>" + comment + "</COMMENT>\n<FUNCNAME>" + name + "</FUNCNAME>";
        StringBuilder builder = new StringBuilder();
        builder.append("        {\n");
        appendNumber(builder, "fid", fid, true);
        appendString(builder, "project", project, true);
        appendString(builder, "version", version, true);
        appendString(builder, "compiler", compiler, true);
        appendString(builder, "arch", arch, true);
        appendString(builder, "bit", bit, true);
        appendString(builder, "opti", opti, true);
        appendString(builder, "md5", md5, true);
        appendString(builder, "smd5", smd5, true);
        appendString(builder, "pcode", pcode, true);
        appendString(builder, "comment", comment, true);
        appendString(builder, "name", name, true);
        appendString(builder, "comment_and_name", commentAndName, false);
        builder.append("        }");
        return builder.toString();
    }

    private void appendNumber(StringBuilder builder, String key, int value, boolean comma) {
        builder.append("            \"").append(key).append("\": ").append(value);
        builder.append(comma ? ",\n" : "\n");
    }

    private void appendString(StringBuilder builder, String key, String value, boolean comma) {
        builder.append("            \"").append(key).append("\": \"").append(jsonEscape(value)).append("\"");
        builder.append(comma ? ",\n" : "\n");
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

    private String md5OfFile(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        BufferedInputStream input = new BufferedInputStream(new FileInputStream(file));
        try {
            byte[] buffer = new byte[1024 * 1024];
            int read;
            while ((read = input.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
        } finally {
            input.close();
        }
        byte[] bytes = digest.digest();
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            builder.append(String.format("%02x", bytes[i] & 0xff));
        }
        return builder.toString();
    }

    private String stripExtension(String name) {
        int index = name.lastIndexOf('.');
        return index > 0 ? name.substring(0, index) : name;
    }

    private String joinUnique(List<String> values, String separator) {
        HashSet<String> seen = new HashSet<String>();
        StringBuilder builder = new StringBuilder();
        for (String value : values) {
            if (seen.contains(value)) {
                continue;
            }
            seen.add(value);
            if (builder.length() > 0) {
                builder.append(separator);
            }
            builder.append(value);
        }
        return builder.toString();
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


def normalize_argv(argv):
    argv = list(argv or [])
    if "--" in argv:
        argv = argv[argv.index("--") + 1:]
    return argv


def expand_response_args(argv):
    argv = normalize_argv(argv)
    if len(argv) == 1 and argv[0].startswith("@"):
        path = argv[0][1:]
        with open(path, "r") as handle:
            return json.load(handle)
    return argv


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Export an IDA or Ghidra analysis database to FoC JSON"
    )
    parser.add_argument("binary", help="Path to the input binary file")
    parser.add_argument("output", help="Path to the output JSON file")
    parser.add_argument("--project", default=None, help="Project name to store in JSON")
    parser.add_argument("--version", default="", help="Version string to store in JSON")
    parser.add_argument("--compiler", default="unknown", help="Compiler string to store in JSON")
    parser.add_argument("--arch", default=None, help="Architecture string to store in JSON")
    parser.add_argument("--bit", default=None, help="Bitness string to store in JSON")
    parser.add_argument("--opti", default="unknown", help="Optimization level to store in JSON")
    parser.add_argument("--smd5", default=None, help="Optional stripped-binary md5 override")
    parser.add_argument("--include-library", action="store_true", help="Include library/external functions")
    parser.add_argument("--include-thunks", action="store_true", help="Include thunk functions")
    parser.add_argument(
        "--backend",
        choices=("auto", "ida", "ghidra"),
        default="auto",
        help="Host-mode backend selection",
    )
    parser.add_argument("--ida-path", default=None, help="IDA executable or installation directory")
    parser.add_argument("--ghidra-headless", default=None, help="Path to Ghidra analyzeHeadless")
    parser.add_argument("--ghidra-project-dir", default=None, help="Directory for the temporary Ghidra project")
    parser.add_argument("--keep-ghidra-project", action="store_true", help="Do not delete the Ghidra project")
    args, _unknown = parser.parse_known_args(expand_response_args(argv))
    return args


def ensure_dir(path):
    if path and not os.path.isdir(path):
        os.makedirs(path)


def md5_of_file(path):
    digest = hashlib.md5()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_file(path, data):
    ensure_dir(os.path.dirname(path) or ".")
    if PY2:
        import codecs

        handle = codecs.open(path, "w", "utf-8")
    else:
        handle = open(path, "w", encoding="utf-8")
    try:
        json.dump(data, handle, indent=4, ensure_ascii=False)
        handle.write("\n")
    finally:
        handle.close()


def unique_preserve_order(values):
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def quote_for_backend_arg(value):
    value = str(value)
    if not value:
        return '""'
    if any(ch.isspace() or ch in '"\\' for ch in value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return value


def executable_path(path):
    if not path:
        return None
    path = os.path.expanduser(os.path.expandvars(path))
    if os.path.isfile(path) and os.access(path, os.X_OK):
        return os.path.abspath(path)
    return None


def find_in_path(names):
    path_value = os.environ.get("PATH", "")
    for directory in path_value.split(os.pathsep):
        if not directory:
            continue
        for name in names:
            candidate = os.path.join(directory, name)
            found = executable_path(candidate)
            if found:
                return found
    return None


def find_under_dir(root, relative_names):
    if not root:
        return None
    root = os.path.expanduser(os.path.expandvars(root))
    if os.path.isfile(root):
        return executable_path(root)
    if not os.path.isdir(root):
        return None
    for relname in relative_names:
        found = executable_path(os.path.join(root, relname))
        if found:
            return found
    return None


def find_under_globs(patterns, relative_names):
    import glob

    for pattern in patterns:
        for root in sorted(glob.glob(os.path.expanduser(os.path.expandvars(pattern)))):
            found = find_under_dir(root, relative_names)
            if found:
                return found
    return None


def ida_executable_names():
    if os.name == "nt":
        return ["idat64.exe", "idat.exe", "ida64.exe", "ida.exe"]
    if sys.platform == "darwin":
        return [
            "idat64",
            "idat",
            "ida64",
            "ida",
            "ida.app/Contents/MacOS/ida",
            "IDA Pro.app/Contents/MacOS/ida",
        ]
    return ["idat64", "idat", "ida64", "ida"]


def find_ida_executable(cli_path):
    names = ida_executable_names()
    for value in (
        cli_path,
        os.environ.get("IDA_EXE"),
        os.environ.get("IDA_PATH"),
        os.environ.get("IDA_HOME"),
    ):
        found = find_under_dir(value, names)
        if found:
            return found
    found = find_in_path(names)
    if found:
        return found
    return None


def ghidra_headless_names():
    if os.name == "nt":
        return ["analyzeHeadless.bat", "analyzeHeadless"]
    return ["analyzeHeadless"]


def ghidra_relative_headless_names():
    names = ghidra_headless_names()
    return names + [os.path.join("support", name) for name in names]


def find_ghidra_headless(cli_path):
    for value in (
        cli_path,
        os.environ.get("GHIDRA_HEADLESS"),
        os.environ.get("GHIDRA_HOME"),
        os.environ.get("GHIDRA_INSTALL_DIR"),
    ):
        found = find_under_dir(value, ghidra_relative_headless_names())
        if found:
            return found
    found = find_in_path(ghidra_headless_names())
    if found:
        return found
    found = find_under_globs(
        [
            "~/ghidra*",
            "~/Ghidra*",
            "~/tools/ghidra*",
            "~/tools/Ghidra*",
            "~/apps/ghidra*",
            "~/apps/Ghidra*",
            "~/ango/tools/ghidra*",
            "~/ango/tools/Ghidra*",
        ],
        ghidra_relative_headless_names(),
    )
    if found:
        return found
    for pattern_root in ("/opt", os.path.expanduser("~/tools"), os.path.expanduser("~/apps")):
        if not os.path.isdir(pattern_root):
            continue
        try:
            entries = os.listdir(pattern_root)
        except OSError:
            continue
        for entry in entries:
            if "ghidra" not in entry.lower():
                continue
            found = find_under_dir(os.path.join(pattern_root, entry), ghidra_relative_headless_names())
            if found:
                return found
    return None


def build_backend_argv(args, input_binary, output_json):
    backend_argv = [input_binary, output_json]
    optional_values = [
        ("--project", args.project),
        ("--version", args.version if args.version else None),
        ("--compiler", args.compiler if args.compiler != "unknown" else None),
        ("--arch", args.arch),
        ("--bit", args.bit),
        ("--opti", args.opti if args.opti != "unknown" else None),
        ("--smd5", args.smd5),
    ]
    for option, value in optional_values:
        if value is not None:
            backend_argv.extend([option, str(value)])
    if args.include_library:
        backend_argv.append("--include-library")
    if args.include_thunks:
        backend_argv.append("--include-thunks")
    return backend_argv


def write_response_file(argv):
    import tempfile

    fd, path = tempfile.mkstemp(prefix="bin2json_args_", suffix=".json")
    os.close(fd)
    with open(path, "w") as handle:
        json.dump(argv, handle)
    return path


def run_command(cmd):
    import subprocess

    print("[+] running: {0}".format(" ".join(quote_for_backend_arg(part) for part in cmd)))
    proc = subprocess.Popen(cmd)
    return proc.wait()


def run_ida_headless(ida_path, script_path, input_binary, backend_argv):
    args_file = write_response_file(backend_argv)
    try:
        script_invocation = "{0} {1}".format(
            quote_for_backend_arg(script_path),
            quote_for_backend_arg("@" + args_file),
        )
        cmd = [ida_path, "-A", "-S" + script_invocation, input_binary]
        return run_command(cmd)
    finally:
        try:
            os.unlink(args_file)
        except OSError:
            pass


def run_ghidra_headless(headless_path, script_path, args, input_binary, backend_argv):
    import shutil
    import tempfile

    created_project_dir = None
    script_dir = tempfile.mkdtemp(prefix="bin2json_ghidra_script_")
    java_script_path = os.path.join(script_dir, GHIDRA_JAVA_SCRIPT_NAME)
    with open(java_script_path, "w") as handle:
        handle.write(GHIDRA_JAVA_SCRIPT.lstrip())

    if args.ghidra_project_dir:
        project_dir = os.path.abspath(args.ghidra_project_dir)
        ensure_dir(project_dir)
    else:
        project_dir = tempfile.mkdtemp(prefix="bin2json_ghidra_")
        created_project_dir = project_dir

    try:
        project_name = "bin2json"
        cmd = [
            headless_path,
            project_dir,
            project_name,
            "-import",
            input_binary,
            "-scriptPath",
            script_dir,
            "-postScript",
            GHIDRA_JAVA_SCRIPT_NAME,
        ] + backend_argv
        if not args.keep_ghidra_project:
            cmd.append("-deleteProject")
        return run_command(cmd)
    finally:
        shutil.rmtree(script_dir, ignore_errors=True)
        if created_project_dir and not args.keep_ghidra_project:
            shutil.rmtree(created_project_dir, ignore_errors=True)


def run_host(argv):
    args = parse_args(argv)
    input_binary = os.path.abspath(args.binary)
    output_json = os.path.abspath(args.output)
    if not os.path.isfile(input_binary):
        raise IOError("input binary not found: {0}".format(input_binary))

    script_path = os.path.abspath(__file__)
    backend_argv = build_backend_argv(args, input_binary, output_json)

    if args.backend in ("auto", "ida"):
        ida_path = find_ida_executable(args.ida_path)
        if ida_path:
            print("[+] detected IDA: {0}".format(ida_path))
            return run_ida_headless(ida_path, script_path, input_binary, backend_argv)
        if args.backend == "ida":
            raise RuntimeError("IDA executable was not found")
        print("[+] IDA was not detected; falling back to Ghidra")

    headless_path = find_ghidra_headless(args.ghidra_headless)
    if not headless_path:
        raise RuntimeError(
            "Ghidra analyzeHeadless was not found. Set GHIDRA_HOME, "
            "GHIDRA_HEADLESS, or pass --ghidra-headless."
        )
    print("[+] detected Ghidra: {0}".format(headless_path))
    return run_ghidra_headless(headless_path, script_path, args, input_binary, backend_argv)


def load_ida_modules():
    global ida_funcs, ida_hexrays, ida_ida, ida_lines, ida_name, idautils, idc
    try:
        import ida_funcs as _ida_funcs
        import idautils as _idautils
        import idc as _idc
    except ImportError:
        return False

    try:
        import ida_hexrays as _ida_hexrays
    except ImportError:
        _ida_hexrays = None
    try:
        import ida_ida as _ida_ida
    except ImportError:
        _ida_ida = None
    try:
        import ida_lines as _ida_lines
    except ImportError:
        _ida_lines = None
    try:
        import ida_name as _ida_name
    except ImportError:
        _ida_name = None

    ida_funcs = _ida_funcs
    ida_hexrays = _ida_hexrays
    ida_ida = _ida_ida
    ida_lines = _ida_lines
    ida_name = _ida_name
    idautils = _idautils
    idc = _idc
    return True


def is_ida_runtime():
    return load_ida_modules()


def is_ghidra_runtime():
    return globals().get("currentProgram") is not None


def clean_ida_text(text):
    if ida_lines is not None and hasattr(ida_lines, "tag_remove"):
        try:
            text = ida_lines.tag_remove(text)
        except Exception:
            pass
    return text.rstrip()


def get_ida_inf_object():
    if ida_ida is None:
        return None
    for attr in ("get_inf_structure", "inf_get_inf_structure"):
        getter = getattr(ida_ida, attr, None)
        if getter is not None:
            try:
                return getter()
            except Exception:
                continue
    return None


def detect_ida_arch_and_bit():
    inf = get_ida_inf_object()
    if inf is None:
        return "unknown", "unknown"

    arch = "unknown"
    bit = "unknown"

    try:
        if hasattr(inf, "is_64bit") and inf.is_64bit():
            bit = "64"
        elif hasattr(inf, "is_32bit_exactly") and inf.is_32bit_exactly():
            bit = "32"
    except Exception:
        pass

    proc_name = ""
    for attr in ("procname", "procName"):
        value = getattr(inf, attr, "")
        if value:
            proc_name = str(value)
            break

    proc_name_lower = proc_name.lower()
    if "x86" in proc_name_lower or "metapc" in proc_name_lower:
        arch = "x86"
    elif proc_name:
        arch = proc_name

    return arch, bit


def ida_is_library_function(func_ea):
    try:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return False
        return bool(func.flags & getattr(ida_funcs, "FUNC_LIB", 0))
    except Exception:
        return False


def ida_is_thunk_function(func_ea):
    try:
        func = ida_funcs.get_func(func_ea)
        if func is None:
            return False
        return bool(func.flags & getattr(ida_funcs, "FUNC_THUNK", 0))
    except Exception:
        return False


def ida_function_name(func_ea):
    try:
        name = idc.get_func_name(func_ea)
        if name:
            return name
    except Exception:
        pass
    try:
        name = ida_name.get_name(func_ea)
        if name:
            return name
    except Exception:
        pass
    return "sub_{0:X}".format(func_ea)


def ida_function_comment(func_ea):
    comments = []
    for repeatable in (False, True):
        try:
            comment = idc.get_func_cmt(func_ea, repeatable)
        except Exception:
            comment = None
        if comment:
            comments.append(comment.strip())
    if comments:
        return " ".join(unique_preserve_order(comments))
    return ""


def ida_render_pseudocode(func_ea):
    if ida_hexrays is None:
        return ""

    try:
        if hasattr(ida_hexrays, "init_hexrays_plugin"):
            ida_hexrays.init_hexrays_plugin()
    except Exception:
        pass

    try:
        cfunc = ida_hexrays.decompile(func_ea)
    except Exception:
        return ""

    try:
        lines = cfunc.get_pseudocode()
    except Exception:
        try:
            return clean_ida_text(str(cfunc))
        except Exception:
            return ""

    rendered_lines = []
    for line in lines:
        text = getattr(line, "line", None)
        if text is None:
            text = str(line)
        rendered_lines.append(clean_ida_text(str(text)))

    return "\n".join(rendered_lines).rstrip()


def ida_function_addresses():
    try:
        return idautils.Functions()
    except Exception:
        return []


def build_record(fid, project, version, compiler, arch, bit, opti, md5, smd5, pcode, comment, name):
    comment_and_name = "<COMMENT>{0}</COMMENT>\n<FUNCNAME>{1}</FUNCNAME>".format(comment, name)
    return {
        "fid": fid,
        "project": project,
        "version": version,
        "compiler": compiler,
        "arch": arch,
        "bit": bit,
        "opti": opti,
        "md5": md5,
        "smd5": smd5,
        "pcode": pcode,
        "comment": comment,
        "name": name,
        "comment_and_name": comment_and_name,
    }


def run_ida_export(argv):
    args = parse_args(argv)
    input_binary = os.path.abspath(args.binary)
    output_json = os.path.abspath(args.output)
    if not os.path.isfile(input_binary):
        raise IOError("input binary not found: {0}".format(input_binary))

    project = args.project or os.path.splitext(os.path.basename(input_binary))[0]
    arch, bit = detect_ida_arch_and_bit()
    if args.arch is not None:
        arch = args.arch
    if args.bit is not None:
        bit = args.bit

    binary_md5 = md5_of_file(input_binary)
    smd5 = args.smd5 or binary_md5

    records = []
    for func_ea in ida_function_addresses():
        if not args.include_library and ida_is_library_function(func_ea):
            continue
        if not args.include_thunks and ida_is_thunk_function(func_ea):
            continue
        records.append(
            build_record(
                fid=len(records),
                project=project,
                version=args.version,
                compiler=args.compiler,
                arch=arch,
                bit=bit,
                opti=args.opti,
                md5=binary_md5,
                smd5=smd5,
                pcode=ida_render_pseudocode(func_ea),
                comment=ida_function_comment(func_ea),
                name=ida_function_name(func_ea),
            )
        )

    write_json_file(output_json, records)
    print("[+] exported {0} functions to {1}".format(len(records), output_json))
    return 0


def ghidra_script_args():
    try:
        return list(getScriptArgs())
    except Exception:
        return sys.argv[1:]


def ghidra_string(value):
    if value is None:
        return ""
    return str(value)


def detect_ghidra_arch_and_bit():
    program = globals().get("currentProgram")
    arch = "unknown"
    bit = "unknown"

    try:
        processor = ghidra_string(program.getLanguage().getProcessor())
        processor_lower = processor.lower()
        if "x86" in processor_lower or "80386" in processor_lower:
            arch = "x86"
        elif processor:
            arch = processor
    except Exception:
        pass

    try:
        bit = str(int(program.getDefaultPointerSize()) * 8)
    except Exception:
        pass

    return arch, bit


def ghidra_function_name(function):
    try:
        name = function.getName()
        if name:
            return ghidra_string(name)
    except Exception:
        pass
    try:
        return "sub_{0}".format(function.getEntryPoint())
    except Exception:
        return "sub_unknown"


def ghidra_function_comment(function):
    comments = []
    for method in ("getComment", "getRepeatableComment"):
        try:
            comment = getattr(function, method)()
        except Exception:
            comment = None
        if comment:
            comments.append(ghidra_string(comment).strip())
    if comments:
        return " ".join(unique_preserve_order(comments))
    return ""


def ghidra_is_library_function(function):
    for method in ("isExternal",):
        try:
            if getattr(function, method)():
                return True
        except Exception:
            pass
    try:
        symbol = function.getSymbol()
        if symbol is not None and symbol.isExternal():
            return True
    except Exception:
        pass
    return False


def ghidra_is_thunk_function(function):
    try:
        return bool(function.isThunk())
    except Exception:
        return False


def ghidra_decompiler_interface():
    from ghidra.app.decompiler import DecompInterface

    interface = DecompInterface()
    try:
        interface.openProgram(globals().get("currentProgram"))
    except Exception:
        pass
    return interface


def ghidra_monitor():
    mon = globals().get("monitor")
    if mon is not None:
        return mon
    try:
        from ghidra.util.task import ConsoleTaskMonitor

        return ConsoleTaskMonitor()
    except Exception:
        return None


def ghidra_render_pseudocode(interface, function):
    try:
        result = interface.decompileFunction(function, 60, ghidra_monitor())
    except Exception:
        return ""
    try:
        if result is None or not result.decompileCompleted():
            return ""
        decompiled = result.getDecompiledFunction()
        if decompiled is None:
            return ""
        return ghidra_string(decompiled.getC()).rstrip()
    except Exception:
        return ""


def ghidra_functions():
    program = globals().get("currentProgram")
    try:
        return program.getFunctionManager().getFunctions(True)
    except Exception:
        return []


def run_ghidra_export(argv):
    args = parse_args(argv)
    input_binary = os.path.abspath(args.binary)
    output_json = os.path.abspath(args.output)
    if not os.path.isfile(input_binary):
        raise IOError("input binary not found: {0}".format(input_binary))

    project = args.project or os.path.splitext(os.path.basename(input_binary))[0]
    arch, bit = detect_ghidra_arch_and_bit()
    if args.arch is not None:
        arch = args.arch
    if args.bit is not None:
        bit = args.bit

    binary_md5 = md5_of_file(input_binary)
    smd5 = args.smd5 or binary_md5
    interface = ghidra_decompiler_interface()

    records = []
    for function in ghidra_functions():
        if not args.include_library and ghidra_is_library_function(function):
            continue
        if not args.include_thunks and ghidra_is_thunk_function(function):
            continue
        records.append(
            build_record(
                fid=len(records),
                project=project,
                version=args.version,
                compiler=args.compiler,
                arch=arch,
                bit=bit,
                opti=args.opti,
                md5=binary_md5,
                smd5=smd5,
                pcode=ghidra_render_pseudocode(interface, function),
                comment=ghidra_function_comment(function),
                name=ghidra_function_name(function),
            )
        )

    try:
        interface.dispose()
    except Exception:
        pass

    write_json_file(output_json, records)
    print("[+] exported {0} functions to {1}".format(len(records), output_json))
    return 0


def main(argv=None):
    if is_ida_runtime():
        return run_ida_export(sys.argv[1:] if argv is None else argv)
    if is_ghidra_runtime():
        return run_ghidra_export(ghidra_script_args() if argv is None else argv)
    return run_host(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    raise SystemExit(main())
