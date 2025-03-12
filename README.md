# UnrealXpert - IDA Plugin for Automated Reverse Engineering

🚀 **UnrealXpert** is an **IDA Pro 9.0 Beta plugin** that automates common reverse engineering tasks using **rule-based searches**. The plugin enables flexible **binary pattern searches, string analysis, immediate value lookups, function parameter filtering, and pseudocode execution tracing**.

---
![image](https://github.com/user-attachments/assets/feeeff00-21aa-4fd4-8c1a-f01a842fcc7a)


---

## 📥 Installation
### **1. Download and Install the Plugin**
1. Clone the repository or download the ZIP:
   ```sh
   git clone https://github.com/yourusername/UnrealXpert.git
   ```
2. Move the `UnrealXpert` folder to **IDA's plugin directory**:
   ```
   IDA/plugins/UnrealXpert/
   ```
3. Ensure the plugin structure looks like this:
   ```
   IDA/plugins/UnrealXpert/
   ├── unrealxpert.py  (Main plugin file)
   ├── rules.json      (Configuration file for search rules)
   ├── __init__.py     (Makes it a package)
   ```

### **2. Install Dependencies**
UnrealXpert requires **PyQt5** for the user interface. If it's not installed, run:
   ```sh
   pip install PyQt5
   ```

### **3. Launch IDA Pro and Load the Plugin**
- Open **IDA Pro** and load a binary.
- Press **`Shift + U`** to open UnrealXpert.

---

## 🎮 **How It Works**
### **Rule-Based Reverse Engineering**
UnrealXpert automates the **common manual steps** taken by reverse engineers, such as:
- **Find a string**
- **Follow XRefs** (Cross-references)
- **Check function parameter counts**
- **Trace function calls in pseudocode**
- **Search using binary patterns**
- **Locate immediate values (constants)**

You define **rules** in `rules.json`, and the plugin **automatically executes them** in any order.

---

## 📜 **Usage**
### **Opening UnrealXpert**
- **Press `Shift + U`** to open the plugin window.
- The plugin **loads rules from `rules.json`** and executes them.
- Results are displayed in a **table format** with:
  - ✅ Rule name
  - 📌 Execution status
  - 🎯 Matched function address
  - 🔎 Function name

---

## 📜 Creating Rules
Rules are stored in a JSON file (`rules.json`) located in the **UnrealXpert plugin directory**. A rule consists of multiple steps that execute sequentially.

Each rule must contain:
- A **`name`** (to identify the rule).
- A **`version`** (useful for organizing rules based on Unreal Engine versions).
- A **`steps`** list, where each step performs an operation.

## 📌 Supported Rule Steps

| Step Type         | Description |
|------------------|-------------|
| `"string"` | Searches for a text string inside the binary. |
| `"xref"` | Finds cross-references (XRefs) to a previously found address. |
| `"binary_pattern"` | Searches for a specific byte pattern. |
| `"immediate"` | Searches for an immediate (constant) value inside functions. |
| `"param_count"` | Filters functions based on their parameter count. |
| `"follow_pseudocode"` | Analyzes Hex-Rays pseudocode and follows function calls. |
| `"qword_address"` | Extracts QWord addresses from pseudocode. |

## 📌 Rule Example: Searching for a String and Following XRefs

```json
{
    "name": "StaticFindObject",
    "version": "4.26",
    "steps": [
        {
            "type": "string",
            "value": "MaterialShaderQualitySettingsContainer",
            "exact_match": true
        },
        {
            "type": "xref"
        },
        {
            "type": "follow_pseudocode",
            "depth": 3
        }
    ]
}
```

## 📌 Rule Example: Finding a QWord Reference

```json
{
    "name": "FindQWordReference",
    "version": "4.26",
    "steps": [
        {
            "type": "string",
            "value": "SomeStringReference",
            "exact_match": false
        },
        {
            "type": "xref"
        },
        {
            "type": "qword_address",
            "depth": 2
        }
    ]
}
```

## 📌 Rule Example: Searching by Binary Pattern

```json
{
    "name": "GetNamePlainString",
    "version": "4.26",
    "steps": [
        {
            "type": "binary_pattern",
            "value": "83 79 ? ? 74 ? 48 8B 01 C3 48 8D 05"
        },
        {
            "type": "param_count",
            "count": 3
        }
    ]
}
```

## 📌 Additional Rule Configuration

| Option           | Description |
|----------------|-------------|
| `"exact_match"` | (`true/false`) Used in `"string"` searches to enforce case-sensitive exact matches. |
| `"depth"` | (`1,2,3,...`) Used in `"follow_pseudocode"` and `"qword_address"` to specify which function call or QWord reference to follow. |

## 📌 How to Use the Rules

1. **Create or edit `rules.json`** inside the `UnrealXpert` directory.
2. **Launch IDA Pro** and **press `Shift+U`** to reload the plugin.
3. **View results** in the UnrealXpert window, where matches appear in a table.
4. **Click on an address** in the results table to jump to the disassembly.

---

## 🔧 **Troubleshooting**
### **Common Issues**
| Problem | Solution |
|---------|----------|
| Plugin doesn't show in IDA | Ensure `unrealxpert.py` is in `IDA/plugins/UnrealXpert/`. |
| No results in the table | Check if `rules.json` contains correct patterns. |
| `ModuleNotFoundError: No module named 'PyQt5'` | Run `pip install PyQt5`. |

### **Debugging**
- Open **IDA's Output Window** (`View -> Output Window`).
- Check logs starting with `[UnrealXpert]`.

---

## 📌 **Contributing**
We welcome contributions! To contribute:
1. Fork the repository.
2. Create a feature branch (`git checkout -b new-feature`).
3. Commit changes (`git commit -m "Added new rule type"`).
4. Push to your fork (`git push origin new-feature`).
5. Open a **Pull Request**.

---

## ⚖️ **License**
UnrealXpert is **open-source** under the **MIT License**.

---

## 📬 **Contact**
- **GitHub Issues**: [Open an Issue](https://github.com/yourusername/UnrealXpert/issues)
- **Discord**: Join our **Reverse Engineering** community!
