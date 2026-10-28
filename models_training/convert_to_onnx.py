import os
import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def convert():
    pkl_path = "models_training/model.pkl"
    onnx_output_path = "app/module2_detector/model.onnx"

    if not os.path.exists(pkl_path):
        raise FileNotFoundError(f"Missing {pkl_path}. Please run train_rf.py first.")

    print(f"[*] Loading scikit-learn model from {pkl_path}...")
    rf_model = joblib.load(pkl_path)

    # Define tensor input format: 10 float32 features matching extract_feature_vector()
    initial_type = [('float_input', FloatTensorType([None, 10]))]

    print("[*] Converting model to ONNX format...")
    onnx_model = convert_sklearn(rf_model, initial_types=initial_type)

    # Ensure target output directory exists
    os.makedirs(os.path.dirname(onnx_output_path), exist_ok=True)

    with open(onnx_output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"[+] Successfully generated ONNX model at: {onnx_output_path}")

if __name__ == "__main__":
    convert()