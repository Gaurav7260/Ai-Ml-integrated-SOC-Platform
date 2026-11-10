
import numpy as np
from collections import Counter


def safe_dict(value):
    """Return a dictionary or an empty dictionary."""
    return value if isinstance(value, dict) else {}


def extract_header_features(header):
    """Extract COFF, optional-header and DOS-header features."""

    header = safe_dict(header)
    features = {}

    # COFF header
    coff = safe_dict(header.get("coff"))

    for key, value in coff.items():

        if isinstance(value, list):
            features[f"header_coff_{key}_count"] = len(value)

            for item in value:
                features[f"header_coff_{key}_{item}"] = 1

        elif isinstance(value, (int, float, bool)):
            features[f"header_coff_{key}"] = value

        elif isinstance(value, str):
            features[f"header_coff_{key}"] = value

    # Optional header
    optional = safe_dict(header.get("optional"))

    for key, value in optional.items():

        if isinstance(value, (int, float, bool)):
            features[f"header_optional_{key}"] = value

        elif isinstance(value, str):
            features[f"header_optional_{key}"] = value

    # DOS header
    dos = safe_dict(header.get("dos"))

    for key, value in dos.items():

        if isinstance(value, (int, float, bool)):
            features[f"header_dos_{key}"] = value

    return features


def extract_section_features(section):
    """Extract section statistics, permissions, names and overlay data."""

    section = safe_dict(section)
    features = {}

    # Entry section
    entry = section.get("entry")

    if isinstance(entry, str):
        features["section_entry"] = entry

    # Individual PE sections
    sections = section.get("sections", [])

    if not isinstance(sections, list):
        sections = []

    features["section_count"] = len(sections)

    sizes = []
    virtual_sizes = []
    entropies = []
    size_ratios = []
    vsize_ratios = []

    property_counts = Counter()
    section_name_counts = Counter()

    for item in sections:

        if not isinstance(item, dict):
            continue

        name = item.get("name")

        if isinstance(name, str):
            section_name_counts[name] += 1

        # Numerical section properties
        for key, target in [
            ("size", sizes),
            ("vsize", virtual_sizes),
            ("entropy", entropies),
            ("size_ratio", size_ratios),
            ("vsize_ratio", vsize_ratios)
        ]:

            value = item.get(key)

            if isinstance(value, (int, float)):
                target.append(value)

        # Section permissions and characteristics
        props = item.get("props", [])

        if isinstance(props, list):
            property_counts.update(str(prop) for prop in props)

    # Aggregate numerical statistics
    collections = {
        "size": sizes,
        "vsize": virtual_sizes,
        "entropy": entropies,
        "size_ratio": size_ratios,
        "vsize_ratio": vsize_ratios
    }

    for name, values in collections.items():

        features[f"section_{name}_sum"] = sum(values)

        features[f"section_{name}_mean"] = (
            np.mean(values) if values else 0
        )

        features[f"section_{name}_max"] = (
            max(values) if values else 0
        )

        features[f"section_{name}_min"] = (
            min(values) if values else 0
        )

        features[f"section_{name}_std"] = (
            np.std(values) if len(values) > 1 else 0
        )

    # Section property frequencies
    for prop, count in property_counts.items():
        features[f"section_prop_{prop}_count"] = count

    # Section name frequencies
    for name, count in section_name_counts.items():
        features[f"section_name_{name}_count"] = count

    # Overlay information
    overlay = safe_dict(section.get("overlay"))

    for key, value in overlay.items():

        if isinstance(value, (int, float, bool)):
            features[f"section_overlay_{key}"] = value

    return features


def extract_pe_features(header, section):
    """Combine header and section features into one dictionary."""

    features = {}

    features.update(extract_header_features(header))
    features.update(extract_section_features(section))

    return features

if __name__ == "__main__":
    sample_header = {
        "coff": {
            "machine": "AMD64",
            "number_of_sections": 3
        },
        "optional": {
            "image_base": 4194304
        },
        "dos": {
            "e_magic": 23117
        }
    }

    sample_section = {
        "entry": ".text",
        "sections": [
            {"name": ".text", "size": 1000, "vsize": 1200, "entropy": 6.5},
            {"name": ".data", "size": 500, "vsize": 600, "entropy": 3.2}
        ]
    }

    features = extract_pe_features(sample_header, sample_section)

    print("Total extracted features:", len(features))
    print("\nSample features:")
    for key, value in list(features.items())[:15]:
        print(f"{key}: {value}")
