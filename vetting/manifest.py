"""
vetting/manifest.py

Statically discovers the tools an MCP server declares, without running
it. An MCP server built with MCPServer exposes tools as functions
decorated with @mcp.tool(); this module parses the source with `ast`
(never exec/import, since that IS the untrusted server being vetted)
and extracts each tool's name, docstring, parameter annotations, and
its own source segment for the static checks to inspect.
"""

import ast
from dataclasses import dataclass


@dataclass
class ToolDef:
    name: str
    docstring: str
    params: dict
    node: ast.AST
    source: str


def parse_server_source(path: str):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        source_text = f.read()

    tree = ast.parse(source_text, filename=path)
    tools = []

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_is_tool_decorator(dec) for dec in node.decorator_list):
            continue

        docstring = ast.get_docstring(node) or ""
        params = {
            arg.arg: ast.unparse(arg.annotation) if arg.annotation else "Any"
            for arg in node.args.args
            if arg.arg != "self"
        }
        func_source = ast.get_source_segment(source_text, node) or ""

        tools.append(ToolDef(
            name=node.name,
            docstring=docstring,
            params=params,
            node=node,
            source=func_source,
        ))

    return source_text, tree, tools


def _is_tool_decorator(dec: ast.expr) -> bool:
    # matches both @mcp.tool and @mcp.tool()
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr == "tool"
    if isinstance(target, ast.Name):
        return target.id == "tool"
    return False