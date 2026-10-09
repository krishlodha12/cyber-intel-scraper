"""Score the extractor against the hand-labeled gold set.

usage: python eval/evaluate.py --model qwen2.5:3b --out eval/results_3b.json [--limit N]

Uses the LLM_BASE_URL / LLM_API_KEY from the environment, and exactly the numbered sentences the
gold labels were written against, so sentence numbers line up.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import extract as E  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return round(p, 3), round(r, 3), round(f, 3)


def near(i, gold):
    return any(abs(i - g) <= 1 for g in gold)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    data = {d["id"]: d for d in json.load(open(os.path.join(HERE, "gold_input.json"), encoding="utf-8"))}
    gold = [json.loads(l) for l in open(os.path.join(HERE, "gold_labels.jsonl"), encoding="utf-8")]
    if a.limit:
        gold = gold[: a.limit]
    client = E._client()

    inc = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    ind = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    fix = {"gold_art": 0, "hit": 0, "hit_near": 0, "pred_art_no_gold": 0, "no_gold_art": 0, "pred_sents": 0, "pred_ok": 0}
    imp = dict(fix)
    failures, secs, rows = 0, 0.0, []

    for g in gold:
        d = data[g["id"]]
        t0 = time.time()
        try:
            p = E.ask_pointer(client, d["title"], d["sents"], model=a.model)
        except Exception as ex:  # a failed article counts against the model
            failures += 1
            p = None
            print(f"[eval] FAIL id={g['id']}: {str(ex)[:80]}", flush=True)
        secs += time.time() - t0
        r = E.gate(p, d["title"], d["sents"]) if p else {"inc": False, "india": False, "fix": [], "impact": []}

        k = ("tp" if r["inc"] else "fn") if g["inc"] else ("fp" if r["inc"] else "tn")
        inc[k] += 1
        k = ("tp" if r["india"] else "fn") if g["india"] else ("fp" if r["india"] else "tn")
        ind[k] += 1

        # fix/impact are only scored on articles that really are incidents
        if g["inc"]:
            for name, bucket in (("fix", fix), ("impact", imp)):
                gs, ps = g[name], r[name] if r["inc"] else []
                if gs:
                    bucket["gold_art"] += 1
                    bucket["hit"] += bool(set(gs) & set(ps))
                    bucket["hit_near"] += any(near(i, gs) for i in ps)
                else:
                    bucket["no_gold_art"] += 1
                    bucket["pred_art_no_gold"] += bool(ps)
                bucket["pred_sents"] += len(ps)
                bucket["pred_ok"] += sum(1 for i in ps if near(i, gs))
        rows.append({"id": g["id"], "gold_inc": g["inc"], "pred_inc": r["inc"], "gold_india": g["india"],
                     "pred_india": r["india"], "gold_fix": g["fix"], "pred_fix": r["fix"],
                     "gold_impact": g["impact"], "pred_impact": r["impact"]})
        print(f"[eval] {len(rows):3}/{len(gold)} id={g['id']:<5} inc gold={g['inc']} pred={int(r['inc'])}", flush=True)

    def rate(n, d):
        return round(n / d, 3) if d else None

    result = {
        "model": a.model, "articles": len(gold), "failures": failures,
        "sec_per_article": round(secs / len(gold), 1),
        "incident": dict(zip(("precision", "recall", "f1"), prf(inc["tp"], inc["fp"], inc["fn"])),
                         accuracy=rate(inc["tp"] + inc["tn"], len(gold)), **inc),
        "india": dict(zip(("precision", "recall", "f1"), prf(ind["tp"], ind["fp"], ind["fn"])), **ind),
        "fix": {"articles_with_gold_fix": fix["gold_art"], "found_exact": rate(fix["hit"], fix["gold_art"]),
                "found_within_1_sentence": rate(fix["hit_near"], fix["gold_art"]),
                "predicted_when_none_exists": rate(fix["pred_art_no_gold"], fix["no_gold_art"]),
                "precision_within_1": rate(fix["pred_ok"], fix["pred_sents"])},
        "impact": {"articles_with_gold_impact": imp["gold_art"], "found_exact": rate(imp["hit"], imp["gold_art"]),
                   "found_within_1_sentence": rate(imp["hit_near"], imp["gold_art"]),
                   "predicted_when_none_exists": rate(imp["pred_art_no_gold"], imp["no_gold_art"]),
                   "precision_within_1": rate(imp["pred_ok"], imp["pred_sents"])},
        "rows": rows,
    }
    json.dump(result, open(a.out, "w", encoding="utf-8"), indent=1)
    summary = {k: v for k, v in result.items() if k != "rows"}
    print("\n=== RESULT ===\n" + json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
