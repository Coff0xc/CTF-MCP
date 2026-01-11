"""
Workflow system for CTF-MCP
Inspired by CTFCrackTools' visual node-based workflow system

Provides automated CTF challenge solving workflows
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import json


class NodeStatus(Enum):
    """Workflow node execution status"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowNode:
    """
    Represents a single node in the workflow

    Inspired by CTFCrackTools' node-based system
    """
    id: str
    name: str
    tool: str
    params: Dict[str, Any]
    next_nodes: List[str] = field(default_factory=list)
    condition: Optional[str] = None  # Conditional execution
    status: NodeStatus = NodeStatus.PENDING
    result: Any = None
    error: Optional[str] = None


class Workflow:
    """
    CTF workflow orchestrator

    Features:
    - Node-based execution flow
    - Conditional branching
    - Result passing between nodes
    - Error handling and recovery
    """

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.nodes: Dict[str, WorkflowNode] = {}
        self.start_node: Optional[str] = None
        self.context: Dict[str, Any] = {}

    def add_node(self, node: WorkflowNode):
        """Add a node to the workflow"""
        self.nodes[node.id] = node

    def set_start_node(self, node_id: str):
        """Set the starting node"""
        if node_id not in self.nodes:
            raise ValueError(f"Node {node_id} not found")
        self.start_node = node_id

    def execute(self, initial_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute the workflow

        Args:
            initial_context: Initial context variables

        Returns:
            Workflow execution results
        """
        if not self.start_node:
            raise ValueError("No start node set")

        # Initialize context
        self.context = initial_context or {}
        self.context["workflow_results"] = {}

        # Execute from start node
        current_node_id = self.start_node
        execution_path = []

        while current_node_id:
            node = self.nodes[current_node_id]
            execution_path.append(current_node_id)

            # Execute node
            try:
                node.status = NodeStatus.RUNNING
                result = self._execute_node(node)
                node.result = result
                node.status = NodeStatus.SUCCESS

                # Store result in context
                self.context["workflow_results"][node.id] = result

            except Exception as e:
                node.status = NodeStatus.FAILED
                node.error = str(e)
                # Stop execution on error
                break

            # Determine next node
            current_node_id = self._get_next_node(node)

        # Return execution summary
        return {
            "workflow": self.name,
            "status": self._get_workflow_status(),
            "execution_path": execution_path,
            "results": self.context["workflow_results"],
            "nodes": {
                node_id: {
                    "status": node.status.value,
                    "result": node.result,
                    "error": node.error
                }
                for node_id, node in self.nodes.items()
            }
        }

    def _execute_node(self, node: WorkflowNode) -> Any:
        """Execute a single node"""
        # Replace context variables in params
        params = self._resolve_params(node.params)

        # Execute tool (this would call the actual CTF-MCP tool)
        # For now, return a placeholder
        return f"Executed {node.tool} with params {params}"

    def _resolve_params(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve context variables in parameters"""
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                # Context variable reference
                var_name = value[1:-1]
                resolved[key] = self.context.get(var_name, value)
            else:
                resolved[key] = value
        return resolved

    def _get_next_node(self, node: WorkflowNode) -> Optional[str]:
        """Determine the next node to execute"""
        if not node.next_nodes:
            return None

        # If there's a condition, evaluate it
        if node.condition:
            if self._evaluate_condition(node.condition):
                return node.next_nodes[0] if node.next_nodes else None
            else:
                return node.next_nodes[1] if len(node.next_nodes) > 1 else None

        # Default: return first next node
        return node.next_nodes[0]

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate a condition string"""
        # Simple condition evaluation
        # Format: "result.contains('success')"
        try:
            # This is a simplified version
            # In production, use a safe expression evaluator
            return eval(condition, {"context": self.context})
        except:
            return False

    def _get_workflow_status(self) -> str:
        """Get overall workflow status"""
        statuses = [node.status for node in self.nodes.values()]

        if any(s == NodeStatus.FAILED for s in statuses):
            return "failed"
        elif all(s == NodeStatus.SUCCESS for s in statuses):
            return "success"
        elif any(s == NodeStatus.RUNNING for s in statuses):
            return "running"
        else:
            return "pending"

    def to_json(self) -> str:
        """Export workflow to JSON"""
        data = {
            "name": self.name,
            "description": self.description,
            "start_node": self.start_node,
            "nodes": [
                {
                    "id": node.id,
                    "name": node.name,
                    "tool": node.tool,
                    "params": node.params,
                    "next_nodes": node.next_nodes,
                    "condition": node.condition
                }
                for node in self.nodes.values()
            ]
        }
        return json.dumps(data, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> 'Workflow':
        """Import workflow from JSON"""
        data = json.loads(json_str)
        workflow = cls(data["name"], data.get("description", ""))

        for node_data in data["nodes"]:
            node = WorkflowNode(
                id=node_data["id"],
                name=node_data["name"],
                tool=node_data["tool"],
                params=node_data["params"],
                next_nodes=node_data.get("next_nodes", []),
                condition=node_data.get("condition")
            )
            workflow.add_node(node)

        if data.get("start_node"):
            workflow.set_start_node(data["start_node"])

        return workflow


class CTFWorkflowTemplates:
    """
    Pre-built workflow templates for common CTF scenarios

    Inspired by CTFCrackTools' template system
    """

    @staticmethod
    def web_recon_workflow() -> Workflow:
        """Web reconnaissance workflow"""
        workflow = Workflow(
            name="web_recon",
            description="Comprehensive web application reconnaissance"
        )

        # Node 1: Technology detection
        workflow.add_node(WorkflowNode(
            id="tech_detect",
            name="Detect Technologies",
            tool="web_tech_detect",
            params={"url": "{target}"},
            next_nodes=["port_scan"]
        ))

        # Node 2: Port scan
        workflow.add_node(WorkflowNode(
            id="port_scan",
            name="Port Scan",
            tool="port_scan",
            params={"target": "{target}", "ports": "80,443,8080,8443"},
            next_nodes=["dir_scan"]
        ))

        # Node 3: Directory scan
        workflow.add_node(WorkflowNode(
            id="dir_scan",
            name="Directory Scan",
            tool="dir_bruteforce",
            params={"url": "{target}"},
            next_nodes=["vuln_scan"]
        ))

        # Node 4: Vulnerability scan
        workflow.add_node(WorkflowNode(
            id="vuln_scan",
            name="Vulnerability Scan",
            tool="vuln_check",
            params={"url": "{target}"},
            next_nodes=[]
        ))

        workflow.set_start_node("tech_detect")
        return workflow

    @staticmethod
    def crypto_analysis_workflow() -> Workflow:
        """Cryptography analysis workflow"""
        workflow = Workflow(
            name="crypto_analysis",
            description="Automated cryptography challenge analysis"
        )

        # Node 1: Identify encoding
        workflow.add_node(WorkflowNode(
            id="identify",
            name="Identify Encoding",
            tool="crypto_identify",
            params={"data": "{ciphertext}"},
            next_nodes=["decode"]
        ))

        # Node 2: Decode
        workflow.add_node(WorkflowNode(
            id="decode",
            name="Decode",
            tool="crypto_decode",
            params={"data": "{ciphertext}", "method": "{detected_method}"},
            next_nodes=["analyze"]
        ))

        # Node 3: Analyze
        workflow.add_node(WorkflowNode(
            id="analyze",
            name="Analyze Result",
            tool="crypto_analyze",
            params={"data": "{decoded_data}"},
            next_nodes=[]
        ))

        workflow.set_start_node("identify")
        return workflow

    @staticmethod
    def pwn_exploit_workflow() -> Workflow:
        """Binary exploitation workflow"""
        workflow = Workflow(
            name="pwn_exploit",
            description="Binary exploitation workflow"
        )

        # Node 1: Binary analysis
        workflow.add_node(WorkflowNode(
            id="analyze",
            name="Analyze Binary",
            tool="pwn_checksec",
            params={"binary": "{binary_path}"},
            next_nodes=["find_vuln"]
        ))

        # Node 2: Find vulnerability
        workflow.add_node(WorkflowNode(
            id="find_vuln",
            name="Find Vulnerability",
            tool="pwn_find_vuln",
            params={"binary": "{binary_path}"},
            next_nodes=["craft_exploit"]
        ))

        # Node 3: Craft exploit
        workflow.add_node(WorkflowNode(
            id="craft_exploit",
            name="Craft Exploit",
            tool="pwn_exploit_gen",
            params={"vuln_type": "{vuln_type}", "binary": "{binary_path}"},
            next_nodes=[]
        ))

        workflow.set_start_node("analyze")
        return workflow
