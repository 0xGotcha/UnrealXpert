# UnrealXpert - IDA Plugin for Automated Reverse Engineering

🚀 **UnrealXpert** is an **IDA Pro 9.0 Beta plugin** that automates common reverse engineering tasks using **rule-based searches**. The plugin enables flexible **binary pattern searches, string analysis, immediate value lookups, function parameter filtering, and pseudocode execution tracing**.

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

## 🛠 **Defining Rules (`rules.json`)**
Rules are stored in `rules.json` and **support flexible execution orders**.

### **Rule Format**
```json
[
  {
    "name": "Find AI Decision Function",
    "version": "5.0",
    "steps": [
      { "type": "string", "value": "AI Decision Making" },
      { "type": "xref" },
      { "type": "param_count", "count": 2 }
    ]
  }
]
```
### 🔹 **Supported Search Types**
| Type              | Description |
|-------------------|-------------|
| `string`         | Search for a specific string. |
| `binary_pattern` | Search using a **byte signature** (e.g., `48 8B ?? ?? ?? ?? ?? E8`). |
| `immediate`      | Search for **immediate values** (e.g., `9.81`, `250.0`). |
| `xref`           | Find **functions that reference** the previous result. |
| `param_count`    | Filter functions by **number of parameters**. |
| `follow_pseudocode` | Follow **Nth function call inside decompiled pseudocode**. |

---

## 🚀 **Example Rules**
### ✅ **Binary Search → XRef → Pseudocode**
```json
[
  {
    "name": "Trace Damage Calculation",
    "version": "4.26",
    "steps": [
      { "type": "binary_pattern", "value": "F3 0F ?? ?? ?? ?? ?? ?? ?? ?? E8" },
      { "type": "xref" },
      { "type": "follow_pseudocode", "depth": 3 }
    ]
  }
]
```
✔ **Finds the binary pattern**  
✔ **Follows references**  
✔ **Traces 3 function calls in pseudocode**  

---

### ✅ **String Search → XRef → Parameter Filter**
```json
[
  {
    "name": "Identify Game Initialization",
    "version": "5.0",
    "steps": [
      { "type": "string", "value": "Game Initialized" },
      { "type": "xref" },
      { "type": "param_count", "count": 3 },
      { "type": "follow_pseudocode", "depth": 2 }
    ]
  }
]
```
✔ **Finds `"Game Initialized"`**  
✔ **Finds functions that reference it**  
✔ **Filters functions with 3 parameters**  
✔ **Follows execution 2 levels deep**  

---

### ✅ **Immediate Value Search → Pseudocode**
```json
[
  {
    "name": "Locate Gravity Modifier",
    "version": "5.1",
    "steps": [
      { "type": "immediate", "value": 9.81 },
      { "type": "follow_pseudocode", "depth": 1 }
    ]
  }
]
```
✔ **Finds constant `9.81` in functions**  
✔ **Follows 1 function call deep in pseudocode**  

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
