# AI-ML Integrated SOC Platform
# Dataset 1 – Data Understanding, Duplicate Analysis & Metadata Enrichment Audit

## 1. Project Overview

The AI-ML Integrated SOC Platform aims to analyze security-related data, identify malicious files, extract useful security intelligence, and generate evidence-based malware analysis results.

As part of the platform, we are working with Windows PE malware datasets containing file hashes, detection information, malware family information, PE file properties, behavioral information, and threat intelligence enrichment.

The objective of this preprocessing phase is to understand the dataset, examine data quality, identify duplicate malware records, investigate metadata inconsistencies, and evaluate the availability of malware enrichment information.

### Objectives of this phase

1. Load and inspect the selected malware dataset.
2. Understand the dataset structure and data types.
3. Identify missing values.
4. Investigate duplicate SHA-256 records.
5. Check whether duplicate records contain conflicting metadata.
6. Understand CAPS, TTPS, and MBC enrichment fields.
7. Identify missing and available enrichment information.
8. Determine whether duplicate records can be consolidated safely.
9. Prepare the dataset for subsequent preprocessing and machine learning.

---

# 2. Dataset Selection and Project Structure

## 2.1 Available datasets

The project contains separate training and testing datasets.

The following CSV files were available:

### Test data

- `2024-09-01_2024-09-07_Win64_test_with_nulls.csv`
- `2024-12-08_2024-12-14_Win64_test_with_nulls.csv`

### Train data

- `2024-09-08_2024-09-14_Win64_train_with_nulls.csv`
- `2024-09-15_2024-09-21_Win64_train_with_nulls.csv`

**Important:** Training and testing datasets are separate. We have selected only the first training CSV for the current preprocessing work.

## 2.2 Selected dataset

Dataset variable:

`dataset_1`

Selected file:

`2024-09-08_2024-09-14_Win64_train_with_nulls.csv`

Dataset source:

First training CSV (September 8–14, 2024).

The testing datasets and second training dataset have not been loaded into this notebook's current analysis.

## 2.3 Project directory structure

The observed project structure is:

```text
AI-MI-Integrated-SOC-Platform/
│
├── .venv/
│
├── data/
│   ├── Test data/
│   │   ├── 2024-09-01_2024-09-07_Win64_test_with_nulls.csv
│   │   └── 2024-12-08_2024-12-14_Win64_test_with_nulls.csv
│   │
│   └── Train data/
│       ├── 2024-09-08_2024-09-14_Win64_train_with_nulls.csv
│       └── 2024-09-15_2024-09-21_Win64_train_with_nulls.csv
│
├── notebook/
│   ├── data_preprocessing_dataset_1.ipynb
│   ├── dataset_download.ipynb
│   └── dataset1.md
│
├── src/
│
├── .gitignore
├── .python-version
├── pyproject.toml
├── README.md
└── requirements.txt
```

---

# 3. Loading Required Libraries and Dataset

## 3.1 Importing libraries

We started by importing Pandas and NumPy.

```python
import pandas as pd
import numpy as np
```

### Why these libraries?

| Library | Purpose |
|---|---|
| Pandas | Dataset loading, manipulation, cleaning and analysis |
| NumPy | Numerical operations, missing-value handling and array operations |

## 3.2 Loading the training dataset

```python
dataset_1 = pd.read_csv(
    '../data/2024-09-08_2024-09-14_Win64_train_with_nulls.csv'
)
```

This loads the selected CSV into a Pandas DataFrame named `dataset_1`.

## 3.3 Checking dataset dimensions

```python
dataset_1.shape
```

**Output:**

```text
(20000, 32)
```

### Interpretation

- Total records: 20,000
- Total columns: 32

The dataset contains 20,000 rows and 32 columns.

---

# 4. Initial Dataset Inspection

## 4.1 Checking missing values in the family column

```python
dataset_1['family'].isnull().sum()
```

**Output:**

```text
12072
```

Therefore, 12,072 records have missing malware family information.

## 4.2 Checking missing values in family_confidence

```python
dataset_1['family_confidence'].isnull().sum()
```

**Output:**

```text
12072
```

The same number of records have missing family confidence.

### Interpretation

Both fields contain substantial missing information.

This is important because malware family classification can help the platform identify malware groups and provide contextual threat intelligence.

However, missing family information does not automatically indicate that a file is benign.

We will investigate these fields further during preprocessing.

## 4.3 Checking dataset columns

```python
dataset_1.columns
```

**Output:**

The dataset contains the following 32 columns:

| No. | Column | Description |
|---:|---|---|
| 1 | md5 | MD5 file hash |
| 2 | sha1 | SHA-1 file hash |
| 3 | sha256 | SHA-256 file hash |
| 4 | tlsh | TLSH fuzzy hash |
| 5 | first_submission_date | First submission timestamp |
| 6 | last_analysis_date | Latest analysis timestamp |
| 7 | detection_ratio | Antivirus detection ratio |
| 8 | label | Dataset classification label |
| 9 | file_type | File architecture/type |
| 10 | family | Malware family information |
| 11 | family_confidence | Confidence of family classification |
| 12 | behavior | Behavioral information |
| 13 | file_property | File properties |
| 14 | packer | Packer information |
| 15 | exploit | Exploit information |
| 16 | group | Malware group information |
| 17 | histogram | Byte histogram features |
| 18 | byteentropy | Byte entropy features |
| 19 | strings | Extracted strings |
| 20 | general | General file information |
| 21 | header | PE header information |
| 22 | section | PE section information |
| 23 | imports | Imported functions |
| 24 | exports | Exported functions |
| 25 | datadirectories | PE data directories |
| 26 | richheader | PE rich header information |
| 27 | authenticode | Digital signature information |
| 28 | pefilewarnings | PE parsing warnings |
| 29 | week_id | Dataset week identifier |
| 30 | caps | Malware capability enrichment |
| 31 | ttps | MITRE ATT&CK technique enrichment |
| 32 | mbc | Malware Behavior Catalog enrichment |

---

# 5. Checking SHA-256 Uniqueness and Duplicate Records

SHA-256 is our primary identifier for grouping records belonging to the same file.

We need to understand whether the dataset contains repeated SHA-256 hashes and whether repeated records are identical or contain different information.

## 5.1 Checking SHA-256 statistics

```python
dataset_1['sha256'].describe(include='all')
```

**Observed output:**

```text
count       20000
unique      10000
top         [sample SHA-256]
freq        2
```

### Interpretation

- Total SHA-256 entries: 20,000
- Unique SHA-256 hashes: 10,000
- Most frequent SHA-256 occurrence: 2

This indicates that each SHA-256 hash occurs twice in this dataset.

Therefore, we have 10,000 distinct SHA-256 groups, each represented by two records.

## 5.2 Checking SHA-256 frequency

```python
dataset_1['sha256'].value_counts().value_counts()
```

**Output:**

```text
count
2    10000
```

### Interpretation

All 10,000 unique SHA-256 hashes occur exactly twice.

This confirms that the dataset contains paired records for every unique SHA-256 identifier.

## 5.3 Extracting duplicate records

```python
duplicate_rows = dataset_1[
    dataset_1['sha256'].duplicated(keep=False)
]
```

### Explanation

- `duplicated()` identifies repeated SHA-256 values.
- `keep=False` marks every occurrence of a repeated hash.
- The resulting DataFrame contains both records for each duplicated SHA-256.

## 5.4 Checking exact duplicate rows

```python
print(duplicate_rows.duplicated().sum())
```

**Output:**

```text
2958
```

### Interpretation

The duplicate subset contains 2,958 rows that are exact duplicate rows according to Pandas' comparison across all columns.

This is different from the 10,000 duplicate SHA-256 groups.

Important distinction:

- 10,000 = SHA-256 groups containing two records.
- 2,958 = rows identified as exact duplicates within the extracted duplicate subset.

We should not treat these two values as interchangeable.

## 5.5 Finding the most frequent SHA-256

```python
dataset_1['sha256'].value_counts().idxmax()
```

**Observed output:**

```text
00047dd8d224e115c979a9eb1acd116e7a4a8a72f025941876b8776bea2c39e2
```

This identifies one of the SHA-256 hashes with the maximum frequency.

---

# 6. Investigating Duplicate Metadata Variations

Finding duplicate hashes is not enough.

Two records with the same SHA-256 may contain different metadata because they were collected or analyzed at different times.

We therefore investigated whether duplicate records contain inconsistent values across different columns.

## 6.1 Checking label conflicts

```python
label_conflicts = (
    duplicate_rows.groupby('sha256')['label']
    .nunique()
)

print(
    "Conflicting labels:",
    (label_conflicts > 1).sum()
)
```

**Output:**

```text
Conflicting labels: 0
```

### Interpretation

No SHA-256 group has more than one distinct label.

This is a positive finding because repeated records have consistent classification labels.

## 6.2 Checking MD5 and SHA-1 conflicts

```python
for col in ['md5', 'sha1']:

    result = (
        duplicate_rows.groupby('sha256')[col]
        .nunique()
    )

    print(col)
    print("Conflicting groups:", (result > 1).sum())
```

**Output:**

```text
md5
Conflicting groups: 0

sha1
Conflicting groups: 0
```

### Interpretation

No conflicting MD5 or SHA-1 values were found within the duplicate SHA-256 groups.

This supports the consistency of these file identifiers.

---

# 7. Understanding CAPS, TTPS and MBC Fields

Three important enrichment columns exist in the dataset:

1. CAPS
2. TTPS
3. MBC

These fields provide information that can help the SOC platform understand malware capabilities, observed techniques and malicious behavior.

## 7.1 CAPS – Capabilities

The CAPS field describes capabilities identified in a malware sample.

Examples observed in the dataset include:

- Find graphical window
- Create or open mutex on Windows
- Link function at runtime
- Encode data using XOR
- Get file attributes
- Create thread
- Accept command-line arguments
- Query registry values
- Write files
- Encrypt data using RC4
- Read files
- Hash data using FNV
- Parse credit card information
- Encode data using Base64
- Create directories
- Compress data using zlib
- Parse PE headers

Each capability may include:

- Capability name
- Namespace
- Associated addresses

Example:

```python
[
    {
        'Capability': 'Encode data using xor',
        'Namespace': 'data-manipulation/encoding/xor',
        'Addrs': ['0x140017f30']
    }
]
```

## 7.2 TTPS – MITRE ATT&CK Techniques

The TTPS field contains information about adversary tactics and techniques.

Examples observed:

| Tactic | Technique |
|---|---|
| DISCOVERY | Application Window Discovery [T1010] |
| EXECUTION | Shared Modules [T1129] |
| DEFENSE EVASION | Obfuscated Files or Information [T1027] |
| EXECUTION | Command and Scripting Interpreter [T1059] |
| DISCOVERY | Query Registry [T1012] |
| DISCOVERY | File and Directory Discovery [T1083] |

This information can help the platform map malware behavior to the MITRE ATT&CK framework.

## 7.3 MBC – Malware Behavior Catalog

The MBC field describes malware-related behavior.

Examples observed:

| Objective | Behavior |
|---|---|
| PROCESS | Create Mutex [C0042] |
| DEFENSE EVASION | Obfuscated Files or Information [E1027.m02] |
| DATA | Encode Data [C0026.002] |
| ANTI-BEHAVIORAL ANALYSIS | Dynamic Analysis Evasion [B0003.003] |
| FILE SYSTEM | Get File Attributes [C0049] |
| PROCESS | Create Thread [C0038] |
| EXECUTION | Command and Scripting Interpreter [E1059] |
| OPERATING SYSTEM | Registry [C0036.006] |
| FILE SYSTEM | Writes File [C0052] |
| CRYPTOGRAPHY | Encrypt Data [C0027.009] |
| DATA | Non-Cryptographic Hash [C0030.005] |
| DISCOVERY | File and Directory Discovery [E1083] |

MBC can provide additional behavioral context beyond file-level properties.

---

# 8. Initial Data Type Investigation

We initially inspected the data types of the three enrichment columns.

```python
for col in ['caps', 'ttps', 'mbc']:

    print("\nCOLUMN:", col)

    print("Data types:")
    print(dataset_1[col].apply(type).value_counts())

    print("\nSample values:")
    print(dataset_1[col].head(5).tolist())
```

### Observed output

For all three columns:

```text
<class 'str'>    20000
```

This means every value in CAPS, TTPS and MBC was initially stored as a Python string.

Examples:

```text
'[]'
```

and:

```text
"[{'Capability': 'Create thread', ...}]"
```

### Important finding

Although these values look like Python lists and dictionaries, they are initially strings.

This matters because Pandas cannot directly treat the string `'[]'` as an empty Python list.

We must convert these strings into actual Python objects before performing structured enrichment analysis.

---

# 9. Converting CAPS, TTPS and MBC into Python Objects

We used Python's `ast.literal_eval()` to convert string representations of Python lists and dictionaries into actual Python objects.

## 9.1 Required library

```python
import ast
import pandas as pd
```

## 9.2 Conversion code

```python
for col in ['caps', 'ttps', 'mbc']:

    dataset_1[col] = dataset_1[col].apply(
        lambda x: ast.literal_eval(x)
        if isinstance(x, str) else x
    )
```

### Explanation

| Component | Purpose |
|---|---|
| `ast` | Provides Python abstract syntax tree functionality |
| `ast.literal_eval()` | Safely evaluates supported Python literals without executing arbitrary Python code |
| `isinstance(x, str)` | Checks whether the value is a string |
| `lambda` | Applies a function to every value |
| `dataset_1[col]` | Updates the selected column |

After conversion:

- `'[]'` becomes `[]`.
- A string representing a list of dictionaries becomes an actual list containing dictionaries.

**Important:** `literal_eval()` is appropriate for trusted, valid Python literal representations. If malformed strings exist, they should be handled explicitly rather than silently ignored.

---

# 10. Checking Empty and Non-Empty Enrichment Records

After conversion, we counted how many records contained empty and non-empty enrichment information.

## 10.1 Python code

```python
for col in ['caps', 'ttps', 'mbc']:

    empty = dataset_1[col].apply(
        lambda x: len(x) == 0
    ).sum()

    non_empty = dataset_1[col].apply(
        lambda x: len(x) > 0
    ).sum()

    print(f"\n{col.upper()}")
    print("Empty:", empty)
    print("Non-empty:", non_empty)
```

## 10.2 Actual output

### CAPS

```text
Empty: 12981
Non-empty: 7019
```

### TTPS

```text
Empty: 13724
Non-empty: 6276
```

### MBC

```text
Empty: 13409
Non-empty: 6591
```

## 10.3 Results table

| Column | Empty | Non-empty | Total |
|---|---:|---:|---:|
| CAPS | 12,981 | 7,019 | 20,000 |
| TTPS | 13,724 | 6,276 | 20,000 |
| MBC | 13,409 | 6,591 | 20,000 |

### Interpretation

CAPS contains 7,019 enriched records.

TTPS contains 6,276 enriched records.

MBC contains 6,591 enriched records.

These are record-level counts, not unique SHA-256 counts.

The three enrichment columns contain different amounts of information.

An empty enrichment list means that no corresponding enrichment entries are available in that record. It does not necessarily mean that the file has no malicious behavior.

---

# 11. Investigating the Initial Error: Unhashable List

During the analysis, we encountered this error:

```text
TypeError: unhashable type: 'list'
```

The traceback showed an error inside Pandas' internal factorization/uniqueness processing.

### Why did this happen?

Pandas operations such as `unique()` and `nunique()` generally require values that can be hashed.

Python lists are mutable and unhashable.

For example:

```python
a = [1, 2, 3]

hash(a)
```

This produces an error because lists cannot be used as hash keys.

Our CAPS, TTPS and MBC columns contain lists of dictionaries after conversion.

Therefore, applying `nunique()` directly to these values can fail.

### Solution

We need to normalize nested structures into comparable strings before grouping and counting unique values.

This is why we introduced a normalization function using JSON serialization.

---

# 12. Investigating Enrichment Conflicts Within Duplicate SHA-256 Groups

We wanted to determine whether the two records belonging to the same SHA-256 contained:

- Both empty enrichment values
- Only one enriched record
- Both enriched records

We performed this analysis separately for CAPS, TTPS and MBC.

## 12.1 CAPS analysis

```python
stats = dataset_1.groupby('sha256')['caps'].apply(
    lambda x: sum(len(v) > 0 for v in x)
)

print("Both empty:", (stats == 0).sum())
print("One enriched:", (stats == 1).sum())
print("Both enriched:", (stats == 2).sum())
```

**Actual output:**

```text
CAPS

Both empty: 2981
One enriched: 7019
Both enriched: 0
```

## 12.2 TTPS analysis

```python
stats = dataset_1.groupby('sha256')['ttps'].apply(
    lambda x: sum(len(v) > 0 for v in x)
)

print("Both empty:", (stats == 0).sum())
print("One enriched:", (stats == 1).sum())
print("Both enriched:", (stats == 2).sum())
```

**Actual output:**

```text
TTPS

Both empty: 3724
One enriched: 6276
Both enriched: 0
```

## 12.3 MBC analysis

```python
stats = dataset_1.groupby('sha256')['mbc'].apply(
    lambda x: sum(len(v) > 0 for v in x)
)

print("Both empty:", (stats == 0).sum())
print("One enriched:", (stats == 1).sum())
print("Both enriched:", (stats == 2).sum())
```

**Actual output:**

```text
MBC

Both empty: 3409
One enriched: 6591
Both enriched: 0
```

## 12.4 Combined results

| Enrichment | Both empty | One enriched | Both enriched |
|---|---:|---:|---:|
| CAPS | 2,981 | 7,019 | 0 |
| TTPS | 3,724 | 6,276 | 0 |
| MBC | 3,409 | 6,591 | 0 |

### Important interpretation

For every enrichment column:

- No SHA-256 group has both records enriched.
- Every group with enrichment information has exactly one enriched record.
- The remaining groups have both records empty.

This is an important observation for our future deduplication strategy.

We should investigate whether the two records represent different collection or enrichment snapshots before consolidating them.

---

# 13. Checking All Three Enrichment Fields Together

Next, we examined CAPS, TTPS and MBC simultaneously.

The purpose was to identify how many unique SHA-256 groups contain all three enrichment fields, at least one enrichment field, or none.

## 13.1 Python code

```python
summary = dataset_1.groupby('sha256').agg(
    caps_count=('caps', lambda x: sum(len(v) > 0 for v in x)),
    ttps_count=('ttps', lambda x: sum(len(v) > 0 for v in x)),
    mbc_count=('mbc', lambda x: sum(len(v) > 0 for v in x))
)

all_three = (
    (summary['caps_count'] == 1) &
    (summary['ttps_count'] == 1) &
    (summary['mbc_count'] == 1)
)

print("All three enriched:", all_three.sum())

print(
    "At least one enriched:",
    ((summary[['caps_count', 'ttps_count', 'mbc_count']] > 0)
     .any(axis=1)).sum()
)

print(
    "All three empty:",
    ((summary[['caps_count', 'ttps_count', 'mbc_count']] == 0)
     .all(axis=1)).sum()
)
```

## 13.2 Actual output

```text
All three enriched: 6085

At least one enriched: 7042

All three empty: 2958
```

## 13.3 Results

| Category | Unique SHA-256 groups |
|---|---:|
| All three enriched | 6,085 |
| At least one enriched | 7,042 |
| All three empty | 2,958 |

### Interpretation

Out of 10,000 unique SHA-256 groups:

- 6,085 have enrichment information in all three fields.
- 7,042 have at least one of the three enrichment fields populated.
- 2,958 have no enrichment information in any of the three fields.

**Note:** The all-three-enriched category is a subset of the at-least-one-enriched category. These numbers should not be added together.

The output suggests that the enrichment information is concentrated in one record of each duplicate pair rather than distributed across both records.

---

# 14. Investigating CAPS, TTPS and MBC Metadata Variations

We initially inspected the lengths of enrichment lists within each SHA-256 group.

## 14.1 Python code

```python
for col in ['caps', 'ttps', 'mbc']:

    print(f"\n{col.upper()}")

    result = dataset_1.groupby('sha256')[col].apply(
        lambda x: [len(v) for v in x]
    )

    print(result.head(10))
```

### Observed sample output

CAPS:

```text
00047dd8...    [0, 30]
0006d1a8...    [25, 0]
001aea7d...    [4, 0]
001b3062...    [1, 0]
001dc027...    [2, 0]
```

TTPS:

```text
00047dd8...    [0, 14]
0006d1a8...    [11, 0]
001aea7d...    [0, 0]
001b3062...    [1, 0]
001dc027...    [1, 0]
```

MBC:

```text
00047dd8...    [0, 29]
0006d1a8...    [27, 0]
001aea7d...    [2, 0]
001b3062...    [0, 0]
001dc027...    [2, 0]
```

### Interpretation

The two records belonging to a SHA-256 group can have different enrichment-list lengths.

For example:

```text
CAPS: [0, 30]
```

means:

- First record contains an empty CAPS list.
- Second record contains 30 CAPS entries.

This supports our observation that enrichment information is present in only one of the two records.

However, different list lengths alone do not prove whether the actual enrichment values are inconsistent or complementary.

---

# 15. Identifying Conflicting SHA-256 Groups

We then performed a more comprehensive conflict check across all dataset columns.

The purpose was to identify how many SHA-256 groups contain multiple distinct values for each metadata column.

## 15.1 Earlier conflict analysis

We initially investigated the CAPS, TTPS and MBC columns separately.

**Observed results:**

```text
caps: 7019 conflicting groups
ttps: 6276 conflicting groups
mbc: 6591 conflicting groups

Total columns checked: 31
```

### Interpretation

These counts are consistent with the earlier enrichment analysis:

- CAPS: 7,019 groups have one populated record and one empty record.
- TTPS: 6,276 groups have one populated record and one empty record.
- MBC: 6,591 groups have one populated record and one empty record.

The conflict count here identifies groups with different normalized values. It does not necessarily indicate contradictory malware intelligence.

An empty list versus a populated list is a difference, but it may represent complementary information.

---

# 16. Normalization Function for Metadata Conflict Detection

To avoid the unhashable-list error, we created a normalization function.

## 16.1 Python code

```python
import pandas as pd
import hashlib
import json

def normalize_value(x):

    if isinstance(x, (list, dict)):
        return json.dumps(
            x,
            sort_keys=True,
            default=str
        )

    if pd.isna(x):
        return "<NULL>"

    return str(x)
```

### Explanation

**1. Checking lists and dictionaries**

```python
if isinstance(x, (list, dict)):
```

Checks whether a value is a nested Python data structure.

**2. Converting nested values into JSON strings**

```python
json.dumps(
    x,
    sort_keys=True,
    default=str
)
```

This converts lists and dictionaries into comparable strings.

`sort_keys=True` ensures dictionary keys are serialized in a consistent order.

`default=str` handles values that JSON cannot otherwise serialize.

**3. Handling missing values**

```python
if pd.isna(x):
    return "<NULL>"
```

Converts missing values into a common placeholder.

**4. Converting remaining values into strings**

```python
return str(x)
```

Ensures that all values can be compared consistently.

---

# 17. Updated Comprehensive Conflict Detection Across 31 Columns

We then implemented the complete conflict-detection code.

This checks every column except SHA-256.

## 17.1 Updated Python code

```python
import pandas as pd
import hashlib
import json

def normalize_value(x):

    if isinstance(x, (list, dict)):
        return json.dumps(
            x,
            sort_keys=True,
            default=str
        )

    if pd.isna(x):
        return "<NULL>"

    return str(x)


conflict_results = {}

for col in dataset_1.columns:

    if col == 'sha256':
        continue

    temp = dataset_1[['sha256', col]].copy()

    temp['_normalized'] = temp[col].apply(
        normalize_value
    )

    conflicts = (
        temp.groupby('sha256')['_normalized']
        .nunique()
    )

    count = (conflicts > 1).sum()

    conflict_results[col] = count

    if count > 0:
        print(f"{col}: {count} conflicting groups")

print("\nTotal columns checked:", len(conflict_results))
```

## 17.2 Explanation of the updated code

| Code | Purpose |
|---|---|
| `conflict_results = {}` | Stores conflict counts for each column |
| `for col in dataset_1.columns` | Iterates through dataset columns |
| `if col == 'sha256'` | Identifies the primary grouping identifier |
| `continue` | Skips SHA-256 itself |
| `dataset_1[['sha256', col]].copy()` | Creates a temporary DataFrame containing the hash and current column |
| `apply(normalize_value)` | Converts nested data into comparable representations |
| `groupby('sha256')` | Groups records belonging to the same file hash |
| `nunique()` | Counts distinct values inside each group |
| `conflicts > 1` | Identifies groups with multiple distinct values |
| `.sum()` | Counts the conflicting groups |
| `conflict_results[col] = count` | Stores the result |
| `len(conflict_results)` | Reports the number of columns examined |

## 17.3 Expected output format

```text
family: ...
family_confidence: ...
detection_ratio: ...
caps: ...
ttps: ...
mbc: ...

Total columns checked: 31
```

The exact counts depend on the current dataset.

### Important distinction

A conflicting group means that the two records have different normalized values for that column.

It does not automatically mean the information is incorrect.

For example:

```text
Record 1: []
Record 2: [CAPS enrichment information]
```

This is a difference, but it may be useful complementary information.

Similarly, different analysis dates or antivirus detection ratios can reflect changes in external analysis over time.

---

# 18. Dataset Summary and Verified Observations

## 18.1 Dataset dimensions

| Metric | Result |
|---|---:|
| Total records | 20,000 |
| Total columns | 32 |
| Unique SHA-256 hashes | 10,000 |
| Occurrences per SHA-256 | 2 |
| Exact duplicate rows within duplicate subset | 2,958 |

## 18.2 File type distribution

```text
file_type
Win64    20000
```

All 20,000 records belong to the Win64 file type.

## 18.3 Label distribution

```text
label
1    10000
0    10000
```

| Label | Records |
|---|---:|
| 1 | 10,000 |
| 0 | 10,000 |

The dataset is balanced at the record level.

The exact semantic meaning of labels 0 and 1 should be confirmed from the dataset documentation before assigning names such as benign and malicious.

## 18.4 Missing family information

| Column | Missing records |
|---|---:|
| family | 12,072 |
| family_confidence | 12,072 |

## 18.5 Enrichment availability

| Column | Empty records | Non-empty records |
|---|---:|---:|
| CAPS | 12,981 | 7,019 |
| TTPS | 13,724 | 6,276 |
| MBC | 13,409 | 6,591 |

## 18.6 Enrichment availability by SHA-256 group

| Enrichment | Both empty | One enriched | Both enriched |
|---|---:|---:|---:|
| CAPS | 2,981 | 7,019 | 0 |
| TTPS | 3,724 | 6,276 | 0 |
| MBC | 3,409 | 6,591 | 0 |

## 18.7 Combined enrichment availability

| Category | SHA-256 groups |
|---|---:|
| All three enriched | 6,085 |
| At least one enriched | 7,042 |
| All three empty | 2,958 |

## 18.8 Identifier and label consistency

| Field | Conflicting SHA-256 groups |
|---|---:|
| MD5 | 0 |
| SHA-1 | 0 |
| Label | 0 |

---

# 19. Important Technical Findings

Based on the analysis completed so far, we have identified the following:

### Finding 1: Every SHA-256 appears twice

The dataset contains 20,000 records but only 10,000 unique SHA-256 hashes.

Therefore, the dataset has paired records for every unique file identifier.

### Finding 2: Labels are consistent within duplicate SHA-256 groups

We found zero conflicting label groups.

This means duplicate records have consistent classification labels.

### Finding 3: File identifiers are consistent

No conflicting MD5 or SHA-1 groups were identified.

### Finding 4: Enrichment information is not consistently distributed

For CAPS, TTPS and MBC, every SHA-256 group with enrichment information has exactly one enriched record and one empty record.

### Finding 5: Enrichment fields contain useful complementary information

The three enrichment columns provide malware capabilities, ATT&CK techniques and malware behavior information.

These can become useful features for our evidence-first SOC platform.

### Finding 6: Missing enrichment does not equal benign

An empty CAPS, TTPS or MBC field does not prove that a sample is harmless.

The absence of enrichment may simply mean that no corresponding information was available.

### Finding 7: Duplicate consolidation requires careful handling

We should not simply remove duplicate SHA-256 records using `drop_duplicates()` without investigating their metadata.

Doing so could discard useful enrichment information.

---

# 20. Errors Encountered and Their Solutions

## Error 1: All enrichment values initially appeared as strings

**Problem:**

CAPS, TTPS and MBC were initially stored as strings.

For example:

```python
'[]'
```

**Solution:**

Used `ast.literal_eval()` to convert string representations into actual Python lists and dictionaries.

## Error 2: Unhashable list

**Error:**

```text
TypeError: unhashable type: 'list'
```

**Cause:**

Pandas uniqueness operations could not directly process nested list values.

**Solution:**

Used JSON normalization to convert lists and dictionaries into comparable strings.

## Error 3: Initial empty-value counting was misleading

Initially, checking the columns as strings produced:

```text
Empty: 0
Non-empty: 0
```

This happened because the counting logic expected Python lists, while the values were strings.

After converting the columns with `ast.literal_eval()`, the correct counts were obtained.

---

# 21. Current Preprocessing Status

| Task | Status |
|---|---|
| Dataset selection | Completed |
| Dataset loading | Completed |
| Dataset shape inspection | Completed |
| Column identification | Completed |
| Family missing-value inspection | Completed |
| Family confidence missing-value inspection | Completed |
| SHA-256 uniqueness analysis | Completed |
| Duplicate SHA-256 extraction | Completed |
| Exact duplicate-row inspection | Completed |
| Label conflict analysis | Completed |
| MD5 conflict analysis | Completed |
| SHA-1 conflict analysis | Completed |
| CAPS, TTPS and MBC data-type inspection | Completed |
| CAPS, TTPS and MBC conversion | Completed |
| Enrichment availability analysis | Completed |
| Enrichment analysis by SHA-256 | Completed |
| Combined enrichment analysis | Completed |
| Metadata normalization function | Completed |
| Comprehensive 31-column conflict detection code | Prepared |
| Full conflict-result interpretation | Pending actual updated output review |
| Duplicate metadata consolidation | Pending |
| Final deduplication | Pending |
| Feature engineering | Pending |
| Machine learning preparation | Pending |

---

# 22. Next Steps

The following activities should be performed after reviewing the complete output of the updated conflict-detection code.

1. Analyze all conflicting columns and classify differences into:
   - Complementary information
   - Temporal changes
   - Genuine metadata inconsistencies
   - Missing-versus-populated values

2. Investigate the two records belonging to the same SHA-256.

3. Develop a safe metadata consolidation strategy.

4. Merge useful CAPS, TTPS and MBC information without losing enrichment entries.

5. Investigate the family and family_confidence fields.

6. Examine detection_ratio and its relationship with labels.

7. Perform final deduplication using SHA-256 after defining the consolidation rules.

8. Perform additional data-quality checks.

9. Begin feature engineering.

10. Prepare the consolidated dataset for machine learning.

---

# 23. Important Notes for Future Development

The current notebook is working with only the first training dataset.

We must keep the following distinctions clear:

- Training and testing data must remain separate.
- Duplicate SHA-256 records should be consolidated carefully.
- Enrichment fields should be merged only after understanding their semantics.
- Missing values should not automatically be interpreted as negative evidence.
- The original labels must be preserved and their meaning verified.
- Any preprocessing decisions must be documented so that the same transformations can be applied to future data.

For machine learning, we must also ensure that duplicate SHA-256 samples do not leak across training and testing splits. Otherwise, evaluation results may be artificially optimistic.

**Current milestone:** Dataset 1 has been loaded, inspected, and analyzed for duplicate hashes, enrichment availability and metadata conflicts. We are now preparing to move from dataset auditing toward safe metadata consolidation.
## Missing Value and Empty List Investigation

### 1. Family Classification Missingness

The consolidated dataset contains 10,000 records.

| Metric | Count |
|---|---:|
| Missing family | 6,036 |
| Missing family confidence | 6,036 |
| Both missing | 6,036 |
| Only family missing | 0 |
| Only confidence missing | 0 |

**Finding:** Both columns have perfectly aligned missing values. No independent missingness was observed.

**Decision:** Preserve these records. Do not assign artificial malware family names or confidence scores.

### 2. Empty List Analysis

| Enrichment field | Empty lists | Percentage |
|---|---:|---:|
| CAPS | 2,981 | 29.81% |
| TTPS | 3,724 | 37.24% |
| MBC | 3,409 | 34.09% |

**Finding:** CAPS, TTPS and MBC contain meaningful enrichment availability differences.

Empty lists are treated separately from null values.

**Decision:** Preserve empty lists and populated enrichment information. Do not discard records based on empty enrichment fields.

### 3. Preprocessing Decision

No missing values or empty lists have been modified or removed at this stage.

Further investigation is required before feature engineering and model preparation.

### Handling Source-Level Missing PE Metadata

During feature extraction validation, two records (row positions 1170 and 9254) were identified with 53 missing PE features each.

Further investigation of the original dataset confirmed that both records contained empty JSON objects (`"{}"`) in their `header` and `section` fields.

The investigation established that these missing values originated in the source dataset rather than from errors in the nested parsing or feature-flattening pipeline.

**Treatment:**
- Preserved both records and their original metadata.
- Created a separate exception report containing their SHA256 hashes and reasons for exclusion.
- Excluded these records from the PE-feature training dataset.
- Did not impute missing PE metadata with artificial zero values.

**Result:** The PE modeling dataset contains 9,998 records and retains the original 1,203-feature schema.