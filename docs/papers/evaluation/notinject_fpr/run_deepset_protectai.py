"""Benign FPR check: deepset/deberta-v3-base-injection vs protectai v2 on NotInject (339 benign)
and deepset/prompt-injections test-split benign. Mirrors competitor_rerun.py: softmax, P(injection)>=0.5,
injection_index read from config.id2label, truncation to 512 tokens. Offline (HF cache only)."""
import os, time, torch
os.environ["HF_HUB_OFFLINE"] = "1"; os.environ["HF_DATASETS_OFFLINE"] = "1"
from datasets import load_dataset
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import glob
from datasets import Dataset
CACHE = os.path.expanduser("~/.cache/huggingface/datasets")

import pyarrow as pa

def _arrow(pattern):
    path = glob.glob(os.path.join(CACHE, pattern), recursive=True)[0]
    with pa.memory_map(path) as src:
        try:
            tbl = pa.ipc.open_stream(src).read_all()
        except pa.ArrowInvalid:
            tbl = pa.ipc.open_file(src).read_all()
    return tbl.to_pylist(), tbl.schema

def load_notinject():
    out = []
    for split in ("NotInject_one", "NotInject_two", "NotInject_three"):
        rows, schema = _arrow(f"leolee99___not_inject/**/not_inject-{split}.arrow")
        col = "prompt" if "prompt" in schema.names else next(f.name for f in schema if pa.types.is_string(f.type))
        out += [r[col] for r in rows]
    return out

def load_deepset_benign():
    rows, _ = _arrow("deepset___prompt-injections/**/prompt-injections-test.arrow")
    return [r["text"] for r in rows if r["label"] == 0]

def run(model_id, texts):
    tok = AutoTokenizer.from_pretrained(model_id)
    mdl = AutoModelForSequenceClassification.from_pretrained(model_id).eval()
    id2label = {int(k): v.upper() for k, v in mdl.config.id2label.items()}
    inj_idx = next(i for i, l in id2label.items() if "INJ" in l)
    fp, probs = 0, []
    t0 = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, len(texts), 16):
            batch = texts[i:i+16]
            enc = tok(batch, return_tensors="pt", truncation=True, max_length=512, padding=True)
            p = torch.softmax(mdl(**enc).logits, dim=-1)[:, inj_idx].tolist()
            probs += p
    fp = sum(1 for p in probs if p >= 0.5)
    return fp, len(texts), time.perf_counter() - t0, id2label, sorted(zip(probs, texts), reverse=True)[:3]

ni = load_notinject(); db = load_deepset_benign()
print(f"NotInject benign n={len(ni)}  deepset-test benign n={len(db)}")
for mid in ("deepset/deberta-v3-base-injection", "protectai/deberta-v3-base-prompt-injection-v2"):
    for name, texts in (("NotInject", ni), ("deepset-test-benign", db)):
        fp, n, secs, labels, top = run(mid, texts)
        print(f"{mid:48s} {name:20s} FP={fp}/{n}  FPR={fp/n*100:5.1f}%  ({secs:.0f}s) labels={labels}")
        if name == "NotInject":
            for p, t in top: print(f"      P={p:.3f} :: {t[:90]!r}")
