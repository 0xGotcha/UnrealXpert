import ida_bytes
import ida_ida
import idaapi
import ida_kernwin
import ida_nalt
import ida_xref
import ida_funcs
import idautils
import json
import os
import idc
import ida_hexrays
from PyQt5 import QtWidgets, QtCore

PLUGIN_DIR = os.path.dirname(__file__)
RULES_FILE = os.path.join(PLUGIN_DIR, "rules.json")

class UnrealXpert(ida_kernwin.PluginForm):
    def __init__(self):
        super().__init__()
        self.table = None
        self.rules = self.load_rules()
        self.results = []
        self.xrefs = []
        self.filtered_xrefs = []
        self.current_xrefs = []
        self.xref_index = -1
        self.current_func = None
        self.param_filter = None
        self.immediate_filter = None
        self.binary_filter = None

    def Show(self):
        """ Open the plugin and reload rules when reopening the window. """
        ida_kernwin.msg("[UnrealXpert] Opening window and reloading rules...\n")

        self.rules = self.load_rules()
        if self.table:
            self.table.clearContents()
            self.table.setRowCount(0)

        try:
            super().Show("UnrealXpert", options=ida_kernwin.PluginForm.WOPN_PERSIST)
        except Exception as e:
            ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to open window: {e}\n")

    def on_table_click(self, row, column):
        """ Handle clicks on the table to navigate to disassembly when an address is clicked. """
        if column == 4:  # Address column
            address_item = self.table.item(row, column)
            if address_item and address_item.text() != "N/A":
                address = int(address_item.text(), 16)  # Convert from hex string to integer
                ida_kernwin.jumpto(address)
                ida_kernwin.msg(f"[UnrealXpert] Jumping to address 0x{address:X} in disassembly.\n")

    def OnCreate(self, form):
        """ Create UI components for the dockable window. """
        self.parent = self.FormToPyQtWidget(form)
        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Rule Name", "Version", "Status", "Result", "Address", "Function"])
        self.table.setSelectionBehavior(QtWidgets.QTableWidget.SelectRows)
        self.table.setSelectionMode(QtWidgets.QTableWidget.SingleSelection)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.table)
        self.parent.setLayout(layout)

        # Connect click event to function
        self.table.cellClicked.connect(self.on_table_click)

        ida_kernwin.msg("[UnrealXpert] UI initialized. Running search...\n")
        self.start_search()

    def load_rules(self):
        """ Load search rules from the JSON file. """
        if not os.path.exists(RULES_FILE):
            ida_kernwin.msg("[UnrealXpert] ERROR: Rules file not found: rules.json\n")
            return []
        
        try:
            with open(RULES_FILE, "r") as f:
                rules = json.load(f)
                ida_kernwin.msg(f"[UnrealXpert] Loaded {len(rules)} rules.\n")
                return rules
        except Exception as e:
            ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to load rules: {e}\n")
            return []

    def execute_rule(self, row, rule):
        """ Execute each step in a rule dynamically. """
        ida_kernwin.msg(f"[UnrealXpert] Executing rule: {rule['name']}\n")
        ea = None  

        for step in rule.get("steps", []):
            step_type = step.get("type")

            if step_type == "binary_pattern":
                new_ea = self.search_pattern(row, step["value"])
                if new_ea is not None:
                    ea = new_ea  # Update only if a valid address is found

            elif step_type == "string":
                exact_match = step.get("exact_match", False)  # Default to False
                ea = self.search_generated_strings(row, step["value"], exact_match) 

            elif step_type == "xref":
                if ea is not None:
                    new_ea = self.trace_xrefs(ea, 0, step.get("max_depth", 3))
                    if new_ea is not None:
                        ea = new_ea  
                else:
                    ida_kernwin.msg(f"[UnrealXpert] Skipping XRef step: No valid address from previous steps.\n")

            elif step_type == "param_count":
                if ea is not None:
                    if self.get_param_count(ea) != step["count"]:
                        ida_kernwin.msg(f"[UnrealXpert] Function at 0x{ea:X} does not match parameter count {step['count']}.\n")
                        continue  # Continue execution instead of stopping

            elif step_type == "follow_pseudocode":
                if ea is not None:
                    new_ea = self.follow_pseudocode_calls(ea, step.get("depth", 1))
                    if new_ea is not None:
                        ea = new_ea

            elif step_type == "qword_address":
                if ea is not None:
                    new_qword = self.find_qword_address(ea, step.get("depth", 1))
                    if new_qword is not None:
                        ea = new_qword  

        ida_kernwin.msg(f"[UnrealXpert] Completed execution of rule: {rule['name']}\n")

        if ea:
            func_name = self.get_function_name(ea)
            self.update_table_with_result(row, "✔ Found", f"0x{ea:X}", func_name)
        else:
            self.update_table_with_result(row, "❌ Not Found", "N/A", "N/A")
    
    def follow_pseudocode_calls(self, ea, depth=3):
        """ Follow function calls in pseudocode and return the nth function call's address. """
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("[UnrealXpert] ERROR: Hex-Rays decompiler is required for pseudocode analysis.\n")
            return None

        try:
            decomp = ida_hexrays.decompile(ea)
            if not decomp:
                ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to decompile function at 0x{ea:X}\n")
                return None

            ida_kernwin.msg(f"[UnrealXpert] Following pseudocode calls in function 0x{ea:X}\n")

            class FunctionCallFinder(ida_hexrays.ctree_parentee_t):
                def __init__(self):
                    super().__init__()
                    self.calls = []

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj:
                        self.calls.append(expr.x.obj_ea)  # Get function address
                    return 0  # Continue parsing

            finder = FunctionCallFinder()
            finder.apply_to(decomp.body, None)

            if len(finder.calls) < depth:
                ida_kernwin.msg(f"[UnrealXpert] ERROR: Function at 0x{ea:X} has less than {depth} calls.\n")
                return None

            target_ea = finder.calls[depth - 1]  # Get the nth function call
            ida_kernwin.msg(f"[UnrealXpert] Found function call at 0x{target_ea:X} (depth {depth})\n")
            return target_ea

        except ida_hexrays.DecompilationFailure:
            ida_kernwin.msg(f"[UnrealXpert] ERROR: Hex-Rays failed to decompile function at 0x{ea:X}\n")
            return None

    def find_qword_address(self, ea, depth=1):
        """ Extracts the nth QWord reference in pseudocode. """
        if not ida_hexrays.init_hexrays_plugin():
            ida_kernwin.msg("[UnrealXpert] ERROR: Hex-Rays decompiler is required for QWord analysis.\n")
            return None

        try:
            decomp = ida_hexrays.decompile(ea)
            if not decomp:
                ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to decompile function at 0x{ea:X}\n")
                return None

            ida_kernwin.msg(f"[UnrealXpert] Extracting QWord references from function 0x{ea:X}\n")

            class QWordFinder(ida_hexrays.ctree_parentee_t):
                def __init__(self):
                    super().__init__()
                    self.qwords = []

                def visit_expr(self, expr):
                    # Check if the expression is an immediate QWord reference
                    if expr.op == ida_hexrays.cot_obj and ida_bytes.is_qword(ida_bytes.get_flags(expr.obj_ea)):
                        self.qwords.append(expr.obj_ea)  # Store the QWord address
                    return 0  # Continue parsing

            finder = QWordFinder()
            finder.apply_to(decomp.body, None)

            if len(finder.qwords) < depth:
                ida_kernwin.msg(f"[UnrealXpert] ERROR: Function at 0x{ea:X} has less than {depth} QWord references.\n")
                return None

            target_qword = finder.qwords[depth - 1]  # Get the nth QWord reference
            ida_kernwin.msg(f"[UnrealXpert] Found QWord reference at 0x{target_qword:X} (depth {depth})\n")
            return target_qword

        except ida_hexrays.DecompilationFailure:
            ida_kernwin.msg(f"[UnrealXpert] ERROR: Hex-Rays failed to decompile function at 0x{ea:X}\n")
            return None


    def search_pattern(self, row, pattern):
        ida_kernwin.msg(f"[UnrealXpert] Searching for pattern: {pattern}\n")

        min_ea, max_ea = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
        compiled_pattern = ida_bytes.compiled_binpat_vec_t()
        err = ida_bytes.parse_binpat_str(compiled_pattern, idaapi.get_imagebase(), pattern, 16)

        if err:
            ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to parse pattern '{pattern}': {err}\n")
            self.update_table_with_result(row, "❌ Not Found", "N/A", "N/A")
            return None

        result = ida_bytes.bin_search3(min_ea, max_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)
        match_found = False  

        while result and result[0] != idaapi.BADADDR and result[0] < max_ea:
            ea = result[0]
            func_name = self.get_function_name(ea)
            ida_kernwin.msg(f"[UnrealXpert] Pattern found at 0x{ea:X} in function: {func_name}\n")

            self.update_table_with_result(row, "✔ Found", f"0x{ea:X}", func_name)
            match_found = True

            result = ida_bytes.bin_search3(ea + 1, max_ea, compiled_pattern, ida_bytes.BIN_SEARCH_FORWARD)

        if not match_found:
            self.update_table_with_result(row, "❌ Not Found", "N/A", "N/A")

        return ea if match_found else None


    def start_search(self):
        """ Populate the table and start scanning based on rules. """
        if not self.table:
            ida_kernwin.msg("[UnrealXpert] ERROR: Table not initialized.\n")
            return  

        self.table.setRowCount(len(self.rules))

        for row, rule in enumerate(self.rules):
            self.execute_rule(row, rule)
            
    def search_generated_strings(self, row, search_string, exact_match=False):
        """ Search for a string in extracted strings and analyze its XRefs. """
        ida_kernwin.msg(f"[UnrealXpert] Searching for string: {search_string} (Exact: {exact_match})\n")

        for string in idautils.Strings():
            str_ea = string.ea
            str_value = idc.get_strlit_contents(str_ea, string.length, string.strtype)

            if not str_value:
                continue
            
            decoded_value = str_value.decode(errors='ignore')

            if exact_match:
                if search_string != decoded_value:
                    continue  # Skip non-exact matches
            else:
                if search_string not in decoded_value:
                    continue  # Skip if it's not a partial match

            ida_kernwin.msg(f"[UnrealXpert] Found string match at 0x{str_ea:X}: {decoded_value}\n")
            return str_ea

        return None

        return None
    def get_param_count(self, func_ea):
        """ Retrieve function parameter count using Hex-Rays decompiler if available. """
        func = idaapi.get_func(func_ea)
        if not func:
            return 0
        
        if ida_hexrays.init_hexrays_plugin():
            try:
                decompiled = idaapi.decompile(func.start_ea)
                return decompiled.type.get_nargs() if decompiled else 0
            except ida_hexrays.DecompilationFailure:
                return 0
        return 0

    def trace_xrefs(self, ea, depth, max_depth):
        """ Trace XRefs recursively up to max depth. """
        if depth > max_depth:
            return None

        if isinstance(ea, list):  # Ensure we handle lists properly
            if not ea:  # If the list is empty, return None
                return None
            ea = ea[0]  # Use the first address in the list

        ida_kernwin.msg(f"[UnrealXpert] Tracing XRefs from 0x{ea:X}, depth: {depth}/{max_depth}\n")

        for xref in idautils.XrefsTo(ea):
            parent_func = ida_funcs.get_func(xref.frm)
            if parent_func:
                ida_kernwin.msg(f"[UnrealXpert] XRef found at 0x{xref.frm:X} in function: {self.get_function_name(parent_func.start_ea)}\n")
                return parent_func.start_ea  

        ida_kernwin.msg("[UnrealXpert] No valid XRefs found.\n")
        return None  

    def get_function_name(self, ea):
        """ Retrieve function name. """
        return ida_funcs.get_func_name(ea) or "Unknown Function"

    def update_table_with_result(self, row, result, address, function):
        """ Update the table with search results and include Rule Name & Version. """
        rule = self.rules[row]  # Get the rule details

        self.table.setItem(row, 0, QtWidgets.QTableWidgetItem(rule["name"]))  # Rule Name
        self.table.setItem(row, 1, QtWidgets.QTableWidgetItem(rule["version"]))  # Version
        self.table.setItem(row, 2, QtWidgets.QTableWidgetItem("Completed"))
        if "qword_address" in self.rules[row].get("steps", []):
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(f"QWord: 0x{address}"))
        else:
            self.table.setItem(row, 3, QtWidgets.QTableWidgetItem(result))
        self.table.setItem(row, 4, QtWidgets.QTableWidgetItem(address))
        self.table.setItem(row, 5, QtWidgets.QTableWidgetItem(function))

    QtWidgets.QApplication.processEvents()

class UnrealXpertPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "UnrealXpert - Byte Pattern Search Plugin"
    help = "Loads rules, searches for byte patterns, and updates the table."
    wanted_name = "UnrealXpert"
    wanted_hotkey = "Shift+U"

    def __init__(self):
        self.xpert_window = None

    def init(self):
        ida_kernwin.add_hotkey("Shift+U", self.show_xpert_window)
        return idaapi.PLUGIN_KEEP

    def show_xpert_window(self):
        """ Refresh the rules and reload UnrealXpert when Shift+U is pressed. """
        ida_kernwin.msg("[UnrealXpert] Reloading rules and refreshing plugin...\n")

        # Close the current plugin window if open
        if self.xpert_window:
            try:
                ida_kernwin.close_plugin_form(self.xpert_window._form)  # Correct way to close in IDA 9.0
            except Exception as e:
                ida_kernwin.msg(f"[UnrealXpert] ERROR: Failed to close window: {e}\n")

            self.xpert_window = None  # Reset instance

        # Reload plugin with fresh rules
        self.xpert_window = UnrealXpert()
        self.xpert_window.Show()

    def term(self):
        self.xpert_window = None

    def run(self, arg):
        self.show_xpert_window()

def PLUGIN_ENTRY():
    return UnrealXpertPlugin()
