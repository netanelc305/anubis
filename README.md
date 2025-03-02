# Anubis – Automated IPSW Data Harvester

Anubis is an automated collection framework for extracting data from binary files.
It supports various
collection methods, including regex searching, symbol extraction, class dumping, and IDA-based
analysis.

---

## Collectors

- **Regex-Based File Search** – Locate patterns in files using `ripgrep`.
- **Class Dump Extraction** – Extract Objective-C class information from Mach-O binaries.
- **Protocol selectors Extraction** – Extract Objective-C selectors of given protocol.
- **Plist Conversion** – Convert property list (`plist`) files to structured `YAML` format.
- **Section Extraction** – Retrieve specific sections from Mach-O binaries.
- **Symbol Extraction** – Extract function symbols from binaries using `nm`.
- **Strings Extraction** – Extract and filter strings from binaries using regex patterns.
- **Register Tracking** *(Experimental)* – Analyze register values within functions using IDA Pro.
- **Binary Export** *(Not supported on IDA 9+)* – Extract and export binary analysis results from IDA Pro.

## Installation

### 1. Install Dependencies

```sh
brew install yq ripgrep libmagic
```

### 2. Install Anubis.

```sh
python3 -m pip install anubis-ipsw
```

**To use the IDA-based collectors, `anubis` must be installed on the same Python interpreter as IDA.
You can select the correct interpreter using the `idapyswitch` utility.**

## Usage

### Running Collectors

To collect data based on a rule file:

```sh
anubis collect /path/to/input /path/to/output /path/to/rules.yaml
```

#### Filtering Collectors

Run specific collectors:

```sh
anubis collect /input /output /rules.yaml -c rg -c binexport
```

Exclude specific collectors:

```sh
anubis collect /input /output /rules.yaml -b strings -b section
```

[Rules example](example_rules.yaml)

Pull requests and issues are welcome!  

