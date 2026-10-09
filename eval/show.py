import json, sys
data = json.load(open("eval/gold_input.json", encoding="utf-8"))
b = int(sys.argv[1]); n = 10
for a in data[b*n:(b+1)*n]:
    print(f"\n### id={a['id']} | {a['source']} | {a['title']}")
    for i, s in enumerate(a["sents"], 1):
        print(f"{i}. {s[:120]}")
