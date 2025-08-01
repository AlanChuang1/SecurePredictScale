import joblib
import torch
import numpy as np
import tenseal as ts

from model_def import LSTMPredictor

# === Load Threat Detection ===
iso = joblib.load("models/isoforest.joblib")
threshold = joblib.load("models/if_threshold.pkl")

feature_cols = ["cpu_util", "mem_util", "net_in", "net_out", "disk_read", "disk_write"]

def is_anomaly(payload: dict) -> bool:
    vec = np.array([payload.get(col, 0.0) for col in feature_cols], dtype=float)
    score = iso.decision_function(vec.reshape(1, -1))[0]
    return score < threshold

# === Load DP-LSTM model ===
query_params = {"hidden_size": 64, "num_layers": 2}  # match what you trained with
model = LSTMPredictor(input_size=1,
                      hidden_size=query_params["hidden_size"],
                      num_layers=query_params["num_layers"],
                      output_size=1).cpu().eval()

state_dict = torch.load("models/federated_dp_lstm.pth", map_location="cpu")
model.load_state_dict(state_dict)

# === Extract final FC layer ===
W_fc = state_dict["fc.weight"].cpu().numpy().reshape(-1)
b_fc = float(state_dict["fc.bias"].item())

# === Build TenSEAL Context ===
ctx = ts.context(
    ts.SCHEME_TYPE.CKKS,
    poly_modulus_degree=8192,
    coeff_mod_bit_sizes=[60, 40, 40, 60]
)
ctx.global_scale = 2**40
ctx.generate_galois_keys()

# === LSTM hidden extractor ===
def extract_hidden(x_batch: torch.Tensor) -> np.ndarray:
    with torch.no_grad():
        out, _ = model.lstm(x_batch)  # [B, T, H]
    return out[:, -1, :].cpu().numpy()

# === HE encrypted final layer ===
def fhe_final_layer(h_np: np.ndarray) -> np.ndarray:
    outs = []
    for row in h_np:
        enc_h = ts.ckks_vector(ctx, row.tolist())
        enc_y = enc_h.dot(W_fc.tolist())
        enc_y += b_fc
        outs.append(enc_y.decrypt()[0])
    return np.array(outs).reshape(-1, 1)

# === Inference entrypoint ===
def predict(payload: dict) -> float:
    """
    payload: { "sequence": [...], "features": {...} }
    """
    if is_anomaly(payload["features"]):
        raise ValueError("Anomalous input – blocked by threat detector.")

    # Convert sequence to LSTM input: shape [1, T, 1]
    seq = np.array(payload["sequence"], dtype=np.float32).reshape(1, -1, 1)
    x_tensor = torch.from_numpy(seq)

    h = extract_hidden(x_tensor)         # → shape (1, H)
    pred = fhe_final_layer(h)            # → shape (1, 1)
    return float(pred[0][0])