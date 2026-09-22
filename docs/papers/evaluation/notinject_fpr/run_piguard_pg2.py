"""NotInject FPR + deepset-test-benign FPR for PIGuard and Meta PromptGuard 2.

Extends Fable's scratchpad/deepset_fpr.py harness with:
  - trust_remote_code=True for leolee99/PIGuard
  - injection_index=1 hard-coded (matches competitor_rerun.py COMPETITORS map,
    since PromptGuard 2 labels are LABEL_0/LABEL_1 and no "INJ" string)

Offline (HF cache only). Same threshold P(injection)>=0.5, same truncation,
same batch size 16 as competitor_rerun.py.
"""
import os, time, torch
os.environ["HF_HUB_OFFLINE"] = "1"; os.environ["HF_DATASETS_OFFLINE"] = "1"
os.environ["TRANSFORMERS_VERBOSITY"] = "error"
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import glob, pyarrow as pa
CACHE = os.path.expanduser("~/.cache/huggingface/datasets")


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
        col = "prompt" if "prompt" in schema.names else next(
            f.name for f in schema if pa.types.is_string(f.type)
        )
        out += [r[col] for r in rows]
    return out


def load_deepset_benign():
    rows, _ = _arrow("deepset___prompt-injections/**/prompt-injections-test.arrow")
    return [r["text"] for r in rows if r["label"] == 0]


def run(model_id, texts, trust_remote_code=False, injection_index=1):
    tok = AutoTokenizer.from_pretrained(model_id, trust_remote_code=trust_remote_code)
    mdl = AutoModelForSequenceClassification.from_pretrained(
        model_id, trust_remote_code=trust_remote_code
    ).eval()
    probs = []
    t0 = time.perf_counter()
    with torch.inference_mode():
        for i in range(0, len(texts), 16):
            batch = texts[i : i + 16]
            enc = tok(
                batch, return_tensors="pt", truncation=True, max_length=512, padding=True
            )
            p = torch.softmax(mdl(**enc).logits, dim=-1)[:, injection_index].tolist()
            probs += p
    fp = sum(1 for p in probs if p >= 0.5)
    return fp, len(texts), time.perf_counter() - t0, sorted(zip(probs, texts), reverse=True)[:3]


ni = load_notinject()
db = load_deepset_benign()
print(f"NotInject benign n={len(ni)}  deepset-test benign n={len(db)}")

for mid, trc in (
    ("leolee99/PIGuard", True),
    ("meta-llama/Llama-Prompt-Guard-2-86M", False),
):
    for name, texts in (("NotInject", ni), ("deepset-test-benign", db)):
        try:
            fp, n, secs, top = run(mid, texts, trust_remote_code=trc, injection_index=1)
            print(
                f"{mid:52s} {name:20s} FP={fp}/{n}  FPR={fp/n*100:5.1f}%  ({secs:.0f}s)"
            )
            if name == "NotInject":
                for p, t in top:
                    print(f"      P={p:.3f} :: {t[:90]!r}")
        except Exception as exc:
            print(f"{mid:52s} {name:20s} CANNOT-VERIFY: {type(exc).__name__}: {exc}")
