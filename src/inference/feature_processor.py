
import json
import re
from pathlib import Path

import pandas as pd


# Project paths
PROJECT_ROOT = Path(__file__).resolve().parents[2]

MAPPING_PATH = (
    PROJECT_ROOT
    / "notebook"
    / "processed_dataset_1"
    / "categorical_mappings.json"
)

FEATURE_NAMES_PATH = (
    PROJECT_ROOT
    / "models"
    / "dataset_1"
    / "feature_names.json"
)


def load_mappings():
    with open(MAPPING_PATH, "r") as file:
        return json.load(file)


def load_feature_names():
    with open(FEATURE_NAMES_PATH, "r") as file:
        return json.load(file)


def sanitize_feature_name(name):
    """Apply the LightGBM feature-name sanitization."""
    return re.sub(r"[^A-Za-z0-9_]", "_", str(name))


def normalize_category(value, categories):
    """Match short category names to their saved training labels."""
    if pd.isna(value):
        return "__MISSING__"

    value = str(value)

    if value in categories:
        return value

    for category in categories:
        if category.endswith("_" + value):
            return category

    return value


def process_features(raw_features):
    """
    Convert extracted PE features into the exact
    637-column model input.
    """

    mappings = load_mappings()
    expected_features = load_feature_names()

    df = pd.DataFrame([raw_features])

    categorical_columns = [
        "header_coff_machine",
        "header_optional_subsystem",
        "section_entry"
    ]

    # Normalize the two Windows header categories.
    for column in categorical_columns[:2]:
        if column in df.columns:
            df[column] = df[column].apply(
                lambda value: normalize_category(
                    value,
                    mappings[column]
                )
            )

    # Map unseen section-entry categories to OTHER.
    if "section_entry" in df.columns:
        allowed_entries = mappings["section_entry"]

        df["section_entry"] = df["section_entry"].apply(
            lambda value: (
                value
                if value in allowed_entries
                else "__OTHER__"
            )
        )

    # One-hot encode categorical features.
    present_categoricals = [
        column
        for column in categorical_columns
        if column in df.columns
    ]

    df = pd.get_dummies(
        df,
        columns=present_categoricals,
        prefix=present_categoricals,
        prefix_sep="_",
        dtype=int
    )

    # Convert remaining features to numeric.
    for column in df.columns:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    df = df.fillna(0)

    # Build lookup using sanitized original feature names.
    feature_lookup = {}

    for column in df.columns:
        safe_name = sanitize_feature_name(column)
        feature_lookup[safe_name] = df[column].iloc[0]

    # Reconstruct the exact saved model feature order.
    output = {}

    for model_name in expected_features:
        original_name = re.sub(
            r"_\d+$",
            "",
            model_name
        )

        output[model_name] = feature_lookup.get(
            original_name,
            0
        )

    processed = pd.DataFrame(
        [output],
        columns=expected_features
    )

    # Final validation.
    if processed.shape[1] != 637:
        raise ValueError(
            f"Expected 637 features, got {processed.shape[1]}"
        )

    if processed.isna().sum().sum() != 0:
        raise ValueError("Missing values found in processed features")

    return processed



if __name__ == "__main__":
    from pe_extractor import extract_pe_features

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

    raw_features = extract_pe_features(
        sample_header,
        sample_section
    )

    processed = process_features(raw_features)

    print("Processed shape:", processed.shape)
    print("Missing values:", processed.isna().sum().sum())
    print("Total features:", len(processed.columns))
    print("\nSample encoded features:")
    print(processed.iloc[0, :15])