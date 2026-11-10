
import json
from pathlib import Path

import joblib

from .feature_processor import process_features
from .pe_extractor import extract_pe_features


PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_PATH = PROJECT_ROOT / "models/dataset_1/lightgbm_baseline.pkl"
CONFIG_PATH = PROJECT_ROOT / "models/dataset_1/model_config.json"


# Load trained model and configuration
model = joblib.load(MODEL_PATH)

with open(CONFIG_PATH, "r") as file:
    config = json.load(file)

THRESHOLD = float(config.get("threshold", 0.35))


def predict_from_metadata(header, section):
    """
    Predict whether PE metadata represents benign or malware.
    """

    # Step 1: Extract raw PE features
    raw_features = extract_pe_features(header, section)

    # Step 2: Convert into model-ready features
    processed_features = process_features(raw_features)

    # Step 3: Predict malware probability
    probabilities = model.predict_proba(processed_features)

    malware_probability = float(probabilities[0][1])

    # Step 4: Apply SOC detection threshold
    prediction = (
        1 if malware_probability >= THRESHOLD else 0
    )

    return {
        "prediction": (
            "Malware" if prediction == 1 else "Benign"
        ),
        "malware_probability": round(malware_probability, 6),
        "threshold": THRESHOLD,
        "confidence_percent": round(
            malware_probability * 100, 2
        ),
        "model": "LightGBM Baseline",
        "dataset": "Dataset 1 - Windows PE"
    }


if __name__ == "__main__":

    sample_header = {
        "coff": {
            "machine": "IMAGE_FILE_MACHINE_AMD64",
            "number_of_sections": 3
        },
        "optional": {
            "image_base": 4194304,
            "subsystem": "IMAGE_SUBSYSTEM_WINDOWS_GUI"
        },
        "dos": {
            "e_magic": 23117
        }
    }

    sample_section = {
        "entry": ".text",
        "sections": [
            {
                "name": ".text",
                "size": 1000,
                "vsize": 1200,
                "entropy": 6.5
            },
            {
                "name": ".data",
                "size": 500,
                "vsize": 600,
                "entropy": 3.2
            }
        ]
    }

    result = predict_from_metadata(
        sample_header,
        sample_section
    )

    print("\nPREDICTION RESULT")
    print("-" * 40)

    for key, value in result.items():
        print(f"{key}: {value}")