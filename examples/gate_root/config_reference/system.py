import importlib.util, json, os
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("kernel", os.path.join(_here, "kernel.py"))
_k = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_k)
_W = json.load(open(os.path.join(_here, "model.json")))["weights"]
def predict(features):
    scores = [sum(_k.q(x, w) for x, w in zip(features, row)) for row in _W]
    return max(range(len(scores)), key=lambda c: (scores[c], -c))
def run(frame_path):
    out = []
    for line in open(frame_path):
        if line.strip():
            it = json.loads(line); p = predict(it["features"])
            out.append({"item_id": it["item_id"], "pred": p, "correct": int(p == it["label"])})
    return out
