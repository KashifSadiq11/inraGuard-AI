"""
Base agent — supports Groq (fast, free) and Ollama (local).
Set GROQ_API_KEY in .env to use Groq, otherwise falls back to Ollama.
"""
import os
import json
from typing import Generator
from openai import OpenAI
from dotenv import load_dotenv
from agents.tools import execute_tool

load_dotenv(override=True)

def _get_config():
    groq_key = os.getenv("GROQ_API_KEY", "")
    if groq_key and groq_key != "your_groq_api_key_here":
        return {
            "base_url": "https://api.groq.com/openai/v1",
            "api_key": groq_key,
            "model": os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"),
            "provider": "groq",
        }
    ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
    return {
        "base_url": f"{ollama_url}/v1",
        "api_key": "ollama",
        "model": os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b"),
        "provider": "ollama",
    }

MODEL = _get_config()["model"]

# ─────────────────────────────────────────────────────────────────────────────
# Tool definitions (OpenAI function-calling format)
# ─────────────────────────────────────────────────────────────────────────────

ALL_TOOL_DEFS = [
    {
        "type": "function",
        "function": {
            "name": "parse_log_patterns",
            "description": "Parse raw log text to extract error/warning patterns, repeated messages, and frequency. Use this first on any log input.",
            "parameters": {
                "type": "object",
                "properties": {
                    "log_text": {"type": "string", "description": "Raw log content to analyze"}
                },
                "required": ["log_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "extract_service_dependencies",
            "description": "Identify which downstream services, hosts, and HTTP endpoints appear in logs and their error rates.",
            "parameters": {
                "type": "object",
                "properties": {
                    "log_text": {"type": "string", "description": "Raw log content"}
                },
                "required": ["log_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "scan_config_security",
            "description": "Scan an infrastructure config file for security anti-patterns, misconfigurations, and hardcoded secrets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "config_text": {"type": "string", "description": "Full config file content"},
                    "config_type": {
                        "type": "string",
                        "enum": ["kubernetes", "terraform", "docker"],
                        "description": "Type of infrastructure config",
                    },
                },
                "required": ["config_text", "config_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_resource_limits",
            "description": "Check Kubernetes manifests to see if containers have CPU/memory resource limits defined.",
            "parameters": {
                "type": "object",
                "properties": {
                    "config_text": {"type": "string", "description": "Kubernetes YAML manifest content"}
                },
                "required": ["config_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_diff_scope",
            "description": "Quantify the blast radius of a deployment diff — lines changed, file types, risk indicators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "diff_text": {"type": "string", "description": "Git diff output"}
                },
                "required": ["diff_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "detect_breaking_changes",
            "description": "Detect breaking changes in a diff: removed API endpoints, deleted env vars, dropped DB columns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "diff_text": {"type": "string", "description": "Git diff output"}
                },
                "required": ["diff_text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "parse_pipeline_failure",
            "description": "Parse CI/CD pipeline logs to identify the failing step, exit code, error context, and failure type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pipeline_log": {"type": "string", "description": "Full CI/CD pipeline log output"}
                },
                "required": ["pipeline_log"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_similar_incidents_mock",
            "description": "Look up the knowledge base for past incidents similar to a given error signature.",
            "parameters": {
                "type": "object",
                "properties": {
                    "error_signature": {
                        "type": "string",
                        "enum": ["OOM_KILL", "TIMEOUT", "NETWORK_ERROR", "TEST_FAILURE", "IMAGE_PULL_ERROR", "UNKNOWN"],
                    }
                },
                "required": ["error_signature"],
            },
        },
    },
]


class BaseAgent:
    name: str = "base"
    system_prompt: str = "You are a helpful DevOps assistant."
    allowed_tools: list[str] = []

    def __init__(self, client: OpenAI):
        self.client = client

    @property
    def tools(self):
        return [t for t in ALL_TOOL_DEFS if t["function"]["name"] in self.allowed_tools]

    def run_stream(self, user_message: str) -> Generator[str, None, None]:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_message},
        ]

        while True:
            stream = self.client.chat.completions.create(
                model=MODEL,
                messages=messages,
                tools=self.tools if self.tools else None,
                tool_choice="auto" if self.tools else None,
                stream=True,
                temperature=0.2,
                max_tokens=1024,
            )

            full_text = ""
            tool_calls_acc: dict[int, dict] = {}
            finish_reason = None

            for chunk in stream:
                choice = chunk.choices[0] if chunk.choices else None
                if not choice:
                    continue

                finish_reason = choice.finish_reason
                delta = choice.delta

                if delta.content:
                    full_text += delta.content
                    yield _sse({"type": "text", "chunk": delta.content})

                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in tool_calls_acc:
                            tool_calls_acc[idx] = {"id": "", "name": "", "arguments": ""}
                        if tc.id:
                            tool_calls_acc[idx]["id"] = tc.id
                        if tc.function:
                            if tc.function.name:
                                tool_calls_acc[idx]["name"] = tc.function.name
                                yield _sse({"type": "tool_call", "tool": tc.function.name, "status": "starting"})
                            if tc.function.arguments:
                                tool_calls_acc[idx]["arguments"] += tc.function.arguments

            if not tool_calls_acc:
                messages.append({"role": "assistant", "content": full_text})
                break

            tool_call_list = []
            tool_results = []

            for idx, tc in sorted(tool_calls_acc.items()):
                tool_call_list.append({
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": tc["arguments"]},
                })
                try:
                    args = json.loads(tc["arguments"] or "{}")
                except json.JSONDecodeError:
                    args = {}

                yield _sse({"type": "tool_call", "tool": tc["name"], "status": "executing", "input": args})
                result = execute_tool(tc["name"], args)
                yield _sse({"type": "tool_call", "tool": tc["name"], "status": "done"})

                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result,
                })

            messages.append({
                "role": "assistant",
                "content": full_text or None,
                "tool_calls": tool_call_list,
            })
            messages.extend(tool_results)

        yield _sse({"type": "done"})


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def make_client() -> OpenAI:
    cfg = _get_config()
    global MODEL
    MODEL = cfg["model"]
    return OpenAI(base_url=cfg["base_url"], api_key=cfg["api_key"])
