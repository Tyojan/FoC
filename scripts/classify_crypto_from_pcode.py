#!/usr/bin/env python3
"""Classify whether a function is crypto-related from pcode.

This script uses the FoC-BinLLM model to generate a `comment_and_name`
prediction from pcode, then applies the existing keyword-based crypto label
heuristics from `FoC-Sim/src/utils/evaluate_crypto_label.py`.

Examples:
  python3 scripts/classify_crypto_from_pcode.py \
    --model_path ./FoC-BinLLM-220m-ft \
    --pcode-file sample_pcode.txt

  python3 scripts/classify_crypto_from_pcode.py \
    --model_path ./FoC-BinLLM-220m-ft \
    --pcode "void foo() { ... }"
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch
from rich.progress import Progress
from transformers import AutoConfig, AutoModelForSeq2SeqLM, AutoTokenizer


ROOT_DIR = Path(__file__).resolve().parents[1]
UTILS_DIR = ROOT_DIR / "FoC-Sim" / "src" / "utils"
if str(UTILS_DIR) not in sys.path:
    sys.path.insert(0, str(UTILS_DIR))

from evaluate_crypto_label import get_keywords_from_prediction  # type: ignore  # noqa: E402


COMMENT_RE = re.compile(r"<COMMENT>(.*?)</COMMENT>", re.DOTALL)
FUNCNAME_RE = re.compile(r"<FUNCNAME>(.*?)</FUNCNAME>", re.DOTALL)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Classify crypto-related functions from pcode")
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--pcode", help="Raw pcode text for a single function")
    input_group.add_argument("--pcode-file", help="Path to a text file containing pcode")
    input_group.add_argument("--input-json", help="Path to a JSON file with objects containing a pcode field")

    parser.add_argument("--model_path", required=True, help="Path to the FoC-BinLLM model directory")
    parser.add_argument("--output-json", default="classification_results.json", help="Path to write JSON results (default: classification_results.json)")
    parser.add_argument("--max_src_len", type=int, default=1024, help="Maximum input length")
    parser.add_argument("--max_tgt_len", type=int, default=256, help="Maximum generated output length")
    parser.add_argument("--batch_size", type=int, default=8, help="Number of functions to process per generation batch")
    parser.add_argument("--num_beams", type=int, default=1, help="Beam count for generation (1=greedy decoding, faster)")
    parser.add_argument("--no_repeat_ngram_size", type=int, default=0, help="Prevent repeated n-grams (0=disabled for speed)")
    parser.add_argument("--device", default=None, help="Device to run on, e.g. cuda, cuda:0, cpu")
    parser.add_argument(
        "--include_modes",
        action="store_true",
        help="Treat block/AE mode keywords as crypto-positive as well as crypto class keywords",
    )
    return parser.parse_args()


def load_model(model_path: str, device: torch.device):
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    config = AutoConfig.from_pretrained(model_path, trust_remote_code=True)
    config.hidden_size = config.d_model
    if config.decoder_start_token_id is None:
        config.decoder_start_token_id = tokenizer.bos_token_id
    config.pad_token_id = tokenizer.pad_token_id
    config.eos_token_id = tokenizer.eos_token_id
    config.bos_token_id = tokenizer.bos_token_id
    config.unk_token_id = tokenizer.unk_token_id

    dtype = torch.float16 if device.type == "cuda" else torch.float32
    model = AutoModelForSeq2SeqLM.from_pretrained(
        model_path,
        config=config,
        torch_dtype=dtype,
        trust_remote_code=True,
    )
    model.to(device)
    model.eval()
    return tokenizer, model


def load_samples(args: argparse.Namespace) -> List[Dict[str, Any]]:
    if args.pcode is not None:
        return [{"fid": 0, "pcode": args.pcode}]
    if args.pcode_file is not None:
        path = Path(args.pcode_file)
        text = path.read_text()
        stripped = text.lstrip()
        if stripped.startswith("[") or stripped.startswith("{"):
            try:
                raw = json.loads(text)
            except json.JSONDecodeError:
                raw = None
            else:
                return normalize_json_samples(raw)
        return [{"fid": 0, "pcode": text}]

    raw = json.loads(Path(args.input_json).read_text())
    return normalize_json_samples(raw)


def normalize_json_samples(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, dict) and "pcode" in raw:
        raw = [raw]

    if not isinstance(raw, list):
        raise ValueError("input JSON must be a list of objects or a single object with a 'pcode' field")

    samples: List[Dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or "pcode" not in item:
            raise ValueError("input JSON must contain objects with a 'pcode' field")
        sample = dict(item)
        sample.setdefault("fid", index)
        samples.append(sample)
    return samples


def chunked(items: List[Dict[str, Any]], batch_size: int):
    for start in range(0, len(items), batch_size):
        yield items[start:start + batch_size]


def generate_comment_and_name_batch(
    tokenizer,
    model,
    pcode_list: List[str],
    device: torch.device,
    args: argparse.Namespace,
) -> List[str]:
    inputs = tokenizer(
        pcode_list,
        return_tensors="pt",
        truncation=True,
        max_length=args.max_src_len,
        padding=True,
    )
    inputs = {key: value.to(device) for key, value in inputs.items()}
    
    gen_kwargs = {
        "max_length": args.max_tgt_len,
        "num_beams": args.num_beams,
    }
    if args.num_beams > 1:
        gen_kwargs["early_stopping"] = True
    if args.no_repeat_ngram_size > 0:
        gen_kwargs["no_repeat_ngram_size"] = args.no_repeat_ngram_size
    
    with torch.no_grad():
        generated = model.generate(**inputs, **gen_kwargs)
    return tokenizer.batch_decode(generated, skip_special_tokens=True)


def parse_comment_and_name(text: str) -> Dict[str, str]:
    comment_match = COMMENT_RE.search(text)
    funcname_match = FUNCNAME_RE.search(text)
    comment = comment_match.group(1).strip() if comment_match else text.strip()
    funcname = funcname_match.group(1).strip() if funcname_match else ""
    return {"comment": comment, "name": funcname}


def classify_prediction(
    prediction: Dict[str, str],
    include_modes: bool,
    source_name: Optional[str] = None,
) -> Dict[str, Any]:
    name_for_classification = prediction["name"] or (source_name or "")
    keywords = get_keywords_from_prediction(name=name_for_classification, summary=prediction["comment"])
    if include_modes:
        positive_keywords = set().union(
            keywords["crypto_class"],
            keywords["block_mode"],
            keywords["ae_mode"],
        )
    else:
        positive_keywords = set(keywords["crypto_class"])

    return {
        "crypto_label": bool(positive_keywords),
        "matched_keywords": {
            "crypto_class": sorted(keywords["crypto_class"]),
            "block_mode": sorted(keywords["block_mode"]),
            "ae_mode": sorted(keywords["ae_mode"]),
        },
    }


def main() -> None:
    args = parse_args()
    device = torch.device(args.device or ("cuda" if torch.cuda.is_available() else "cpu"))

    tokenizer, model = load_model(args.model_path, device)
    samples = load_samples(args)
    
    # Pre-calculate total batches for progress bar
    total_batches = (len(samples) + args.batch_size - 1) // args.batch_size

    results: List[Dict[str, Any]] = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing batches...", total=total_batches)
        for batch_samples in chunked(samples, args.batch_size):
            pcode_list = [sample["pcode"] for sample in batch_samples]
            generated_list = generate_comment_and_name_batch(tokenizer, model, pcode_list, device, args)

            for sample, generated in zip(batch_samples, generated_list):
                parsed = parse_comment_and_name(generated)
                classification = classify_prediction(
                    parsed,
                    include_modes=args.include_modes,
                    source_name=sample.get("name"),
                )

                result = {
                    "fid": sample.get("fid"),
                    "pcode": sample["pcode"],
                    "predicted_comment_and_name": generated,
                    "predicted_comment": parsed["comment"],
                    "predicted_name": parsed["name"],
                    **classification,
                }
                if "name" in sample:
                    result["input_name"] = sample["name"]
                if "comment_and_name" in sample:
                    result["target_comment_and_name"] = sample["comment_and_name"]

                results.append(result)
            
            progress.update(task, advance=1)

    output: Any = results[0] if len(results) == 1 else results
    text = json.dumps(output, indent=2, ensure_ascii=False)
    
    # Always write to file
    output_path = Path(args.output_json)
    output_path.write_text(text + "\n")
    progress = Progress()
    with progress:
        task = progress.add_task("[green]✓ Results saved to:", total=None)
    print(f"Results saved to: {output_path.resolve()}")


if __name__ == "__main__":
    main()