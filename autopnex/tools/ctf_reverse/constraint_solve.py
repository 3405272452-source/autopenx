"""Constraint solver tool for CTF reverse engineering challenges.

Generates and executes z3 solver scripts via subprocess.
Does NOT require z3-solver as a hard dependency — generates scripts
and runs them in a subprocess, leveraging script_execute from ctf_crypto.

Useful for:
- Solving keygen/crackme challenges
- Finding inputs that satisfy complex constraints
- Reversing hash/check functions
"""
from __future__ import annotations

import textwrap
from typing import Any, Dict, List

from ..base import BaseTool, ToolResult, register
from ..ctf_crypto.script_execute import script_execute


# ---------------------------------------------------------------------------
# Standalone function interface
# ---------------------------------------------------------------------------


def constraint_solve(
    constraints: str,
    variables: List[str],
    timeout: int = 30,
) -> dict:
    """Solve constraints using z3 via subprocess execution.

    Generates a z3 Python script from the provided constraints and variable
    names, then executes it in a subprocess.

    Args:
        constraints: Python/z3 code string defining the constraints.
            Can be raw z3 constraint expressions or a complete script.
        variables: List of variable names to solve for.
        timeout: Maximum execution time in seconds (default: 30).

    Returns:
        dict with keys: success, solution, script_output.
    """
    result: Dict[str, Any] = {
        "success": False,
        "solution": {},
        "script_output": "",
    }

    if not constraints:
        result["error"] = "constraints is required"
        return result

    if not variables:
        result["error"] = "variables list is required (at least one variable name)"
        return result

    # Validate variable names
    for var in variables:
        if not var.isidentifier():
            result["error"] = f"Invalid variable name: {var!r}"
            return result

    # Enforce timeout bounds
    timeout = max(5, min(timeout, 120))

    # Generate the z3 solver script
    script = _generate_z3_script(constraints, variables)

    # Execute via script_execute (sandboxed subprocess)
    exec_result = script_execute(script, timeout=timeout)

    result["script_output"] = exec_result.get("stdout", "") or exec_result.get("stderr", "")

    if exec_result["success"]:
        # Parse the solution from stdout
        solution = _parse_z3_output(exec_result["stdout"], variables)
        if solution:
            result["success"] = True
            result["solution"] = solution
        else:
            # Script ran but no solution found (unsat or parse error)
            result["success"] = False
            result["error"] = "No solution found (constraints may be unsatisfiable)"
            result["script_output"] = exec_result["stdout"]
    else:
        # Script execution failed
        stderr = exec_result.get("stderr", "")
        if "ModuleNotFoundError" in stderr and "z3" in stderr:
            result["error"] = (
                "z3-solver is not installed. Install with: pip install z3-solver"
            )
        else:
            result["error"] = f"Script execution failed: {stderr[:500]}"

    return result


# ---------------------------------------------------------------------------
# Script generation
# ---------------------------------------------------------------------------


def _generate_z3_script(constraints: str, variables: List[str]) -> str:
    """Generate a complete z3 solver script.

    If the constraints already contain 'from z3 import' or 'import z3',
    treat them as a complete script and just append solution printing.
    Otherwise, wrap them in a standard z3 solver template.
    """
    # Check if constraints are already a complete script
    if "import z3" in constraints or "from z3" in constraints:
        # User provided a complete script — append solution extraction
        return _wrap_complete_script(constraints, variables)

    # Generate a template script wrapping the constraints
    var_declarations = "\n".join(
        f"{var} = BitVec('{var}', 32)" for var in variables
    )

    script = textwrap.dedent(f"""\
        import json
        import sys

        try:
            from z3 import *
        except ImportError:
            print("ERROR: z3-solver not installed", file=sys.stderr)
            sys.exit(1)

        # Declare variables
        {var_declarations}

        # Create solver
        solver = Solver()
        solver.set("timeout", 25000)  # 25 second timeout for z3

        # Add constraints
        {constraints}

        # Solve
        check_result = solver.check()
        if check_result == sat:
            model = solver.model()
            solution = {{}}
            for var_name in {variables!r}:
                var_ref = eval(var_name)
                val = model.evaluate(var_ref)
                # Convert z3 value to Python int/str
                try:
                    solution[var_name] = val.as_long()
                except (AttributeError, Exception):
                    solution[var_name] = str(val)
            print("SAT")
            print(json.dumps(solution))
        elif check_result == unsat:
            print("UNSAT")
        else:
            print("UNKNOWN")
    """)

    return script


def _wrap_complete_script(script: str, variables: List[str]) -> str:
    """Wrap a complete user script with solution output logic."""
    # Add solution printing at the end if not already present
    if "json.dumps" not in script and "print" not in script.split("\n")[-5:]:
        append = textwrap.dedent(f"""\

            # Auto-appended solution extraction
            import json
            if 'solver' in dir() or 's' in dir():
                _solver = solver if 'solver' in dir() else s
                if _solver.check() == sat:
                    _model = _solver.model()
                    _solution = {{}}
                    for _var_name in {variables!r}:
                        try:
                            _var_ref = eval(_var_name)
                            _val = _model.evaluate(_var_ref)
                            try:
                                _solution[_var_name] = _val.as_long()
                            except (AttributeError, Exception):
                                _solution[_var_name] = str(_val)
                        except Exception:
                            pass
                    print("SAT")
                    print(json.dumps(_solution))
                else:
                    print("UNSAT")
        """)
        script += append

    return script


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------


def _parse_z3_output(stdout: str, variables: List[str]) -> Dict[str, Any]:
    """Parse z3 solver output to extract variable solutions."""
    import json

    lines = stdout.strip().splitlines()

    for i, line in enumerate(lines):
        if line.strip() == "SAT":
            # Next line should be JSON solution
            if i + 1 < len(lines):
                try:
                    solution = json.loads(lines[i + 1])
                    if isinstance(solution, dict):
                        return solution
                except (json.JSONDecodeError, IndexError):
                    pass

    # Try to parse the entire output as JSON
    try:
        parsed = json.loads(stdout.strip())
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try to find variable assignments in output
    solution: Dict[str, Any] = {}
    for line in lines:
        for var in variables:
            # Match patterns like "x = 42" or "x: 42"
            import re
            patterns = [
                rf'{re.escape(var)}\s*=\s*(\d+)',
                rf'{re.escape(var)}\s*:\s*(\d+)',
                rf'"{re.escape(var)}"\s*:\s*(\d+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    try:
                        solution[var] = int(match.group(1))
                    except ValueError:
                        solution[var] = match.group(1)
                    break

    return solution if solution else {}


# ---------------------------------------------------------------------------
# Tool class
# ---------------------------------------------------------------------------


@register
class ConstraintSolveTool(BaseTool):
    """Solve constraints using z3 for reverse engineering challenges."""

    category = "ctf_reverse"

    @property
    def name(self) -> str:
        return "constraint_solve"

    @property
    def description(self) -> str:
        return (
            "Solve constraints using z3 theorem prover. Generates and executes "
            "a z3 Python script to find variable values satisfying given constraints. "
            "Useful for crackme/keygen challenges. Requires z3-solver to be installed."
        )

    def parameters_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "constraints": {
                    "type": "string",
                    "description": (
                        "Python/z3 constraint code. Can be raw z3 expressions "
                        "(e.g., 'solver.add(x + y == 10)') or a complete z3 script."
                    ),
                },
                "variables": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of variable names to solve for.",
                },
                "timeout": {
                    "type": "integer",
                    "description": "Maximum execution time in seconds (default: 30).",
                    "default": 30,
                },
            },
            "required": ["constraints", "variables"],
        }

    def _run(self, **kwargs: Any) -> ToolResult:
        constraints = kwargs.get("constraints", "")
        variables = kwargs.get("variables", [])
        timeout = int(kwargs.get("timeout", 30))

        if not constraints:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="constraints is required",
                error="missing_args",
            )

        if not variables:
            return ToolResult(
                success=False,
                tool=self.name,
                summary="variables list is required",
                error="missing_args",
            )

        exec_result = constraint_solve(constraints, variables, timeout)

        if exec_result["success"]:
            solution = exec_result["solution"]
            summary = f"Solved: {solution}"
            return ToolResult(
                success=True,
                tool=self.name,
                summary=summary,
                parsed_data={
                    "solution": solution,
                    "variables": variables,
                },
                raw_output=exec_result.get("script_output", ""),
            )
        else:
            return ToolResult(
                success=False,
                tool=self.name,
                summary=exec_result.get("error", "Constraint solving failed"),
                error=exec_result.get("error", "unknown_error"),
                parsed_data={
                    "script_output": exec_result.get("script_output", ""),
                },
            )
