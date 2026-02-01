"""
CTF-MCP LLM Agent Module

Provides ReAct-based LLM Agent for autonomous CTF challenge solving.

Features:
- Multi-provider support (OpenAI, Anthropic, Ollama)
- ReAct (Reasoning + Acting) architecture
- RAG integration with KnowledgeBase
- Tool bindings for CTF solving

Example usage:
    from ctf_mcp.llm import LLMConfig, ReActAgent
    from ctf_mcp.llm.agent.tools import create_ctf_agent_tools

    # Configure LLM
    config = LLMConfig.from_env()

    # Create agent with tools
    tools = create_ctf_agent_tools()
    agent = ReActAgent(config=config, tools=tools.get_tools_dict())

    # Solve a challenge
    result = await agent.run({
        "description": "Decrypt this message: ...",
        "category": "crypto",
    })

    if result.flag:
        print(f"Found flag: {result.flag}")
"""

from .config import LLMConfig, get_llm_config, set_llm_config

# Lazy imports to avoid import errors when dependencies not installed
def get_react_agent():
    """Get ReActAgent class (lazy import)"""
    from .agent.react import ReActAgent
    return ReActAgent

def get_enhanced_orchestrator():
    """Get EnhancedOrchestrator class (lazy import)"""
    from .integration.enhanced_orchestrator import EnhancedOrchestrator
    return EnhancedOrchestrator

__all__ = [
    "LLMConfig",
    "get_llm_config",
    "set_llm_config",
    "get_react_agent",
    "get_enhanced_orchestrator",
]
